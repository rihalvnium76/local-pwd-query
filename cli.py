'''离线查询系统的数据准备工具与本地 HTTP 服务器。

用法见 DESIGN.md，这里只实现文档规定的行为。
'''

import argparse
import base64
import contextlib
import hashlib
import http.server
import json
import posixpath
import secrets
import shutil
import sys
import tomllib
import urllib.parse
import urllib.request

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import msgpack

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
DOWNLOAD_TIMEOUT = 30
REQUEST_TIMEOUT = 30

DEFAULT_INPUT = './data.toml'
DEFAULT_TOKEN_FILE = './token.toml'
DEFAULT_WEB_DATA_DIR = './'

INDEX_FILE = 'index.html'
DATA_DIR = 'data'
USER_DIR = 'user'
SHARED_DATA_FILE = 'data'

STATIC_DIRS = ('lib', DATA_DIR)

DEPENDENCIES = (
    ('lib/msgpack.min.js', 'https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js'),
)

FILE_KEYS = frozenset({'loc', 'pwd', 'desc', 'author', 'groups'})
GROUP_KEYS = frozenset({'users'})
SOURCE_KEYS = frozenset({'token_file', 'user', 'group', 'file'})


@dataclass(frozen=True, slots=True)
class FileSpec:
    path: str
    loc: str | None
    pwd: str | None
    desc: str | None
    author: str | None
    groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Source:
    users: tuple[str, ...]
    groups: dict[str, tuple[str, ...]]
    files: dict[str, FileSpec]
    token_file: Path


def read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding='utf-8'))
    except tomllib.TOMLDecodeError as error:
        raise SystemExit(f'{path}：{error}') from error


def table_of(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f'{where} 须为表')
    return value


def string_tuple(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f'{where} 须为字符串数组')
    return tuple(value)


def optional_string(table: dict[str, Any], key: str, where: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SystemExit(f'{where} 的 {key} 须为字符串')
    return value


def check_keys(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise SystemExit(f'{where} 出现未知字段：{"、".join(unknown)}')


def validate_virtual_path(path: str, where: str) -> None:
    if not path.startswith('/') or path.endswith('/'):
        raise SystemExit(f'{where} 须以 / 开头且不以 / 结尾：{path}')
    for segment in path[1:].split('/'):
        if not segment or segment != segment.strip():
            raise SystemExit(f'{where} 的名称不能为空或首尾含空白：{path}')


def check_no_shadowing(paths: tuple[str, ...]) -> None:
    known = set(paths)
    for path in sorted(known):
        parent = path.rsplit('/', 1)[0]
        while parent:
            if parent in known:
                raise SystemExit(f'虚拟路径 {parent} 既是文件又是目录：{path}')
            parent = parent.rsplit('/', 1)[0]


def read_source(input_path: Path) -> Source:
    raw = read_toml(input_path)
    check_keys(raw, SOURCE_KEYS, str(input_path))
    user_tables = table_of(raw.get('user', {}), 'user')
    group_tables = table_of(raw.get('group', {}), 'group')
    file_tables = table_of(raw.get('file', {}), 'file')

    users = tuple(user_tables)
    for name, value in user_tables.items():
        where = f'user."{name}"'
        if table_of(value, where):
            raise SystemExit(f'{where} 须为空表')
    groups: dict[str, tuple[str, ...]] = {}
    for name, value in group_tables.items():
        where = f'group."{name}"'
        table = table_of(value, where)
        check_keys(table, GROUP_KEYS, where)
        members = string_tuple(table.get('users', []), f'{where} 的 users')
        for member in members:
            if member not in user_tables:
                raise SystemExit(f'{where} 引用了未定义的用户：{member}')
        groups[name] = members

    files: dict[str, FileSpec] = {}
    for path, value in file_tables.items():
        where = f'file."{path}"'
        table = table_of(value, where)
        check_keys(table, FILE_KEYS, where)
        validate_virtual_path(path, where)
        members = string_tuple(table.get('groups', []), f'{where} 的 groups')
        for member in members:
            if member not in group_tables:
                raise SystemExit(f'{where} 引用了未定义的分组：{member}')
        files[path] = FileSpec(
            path=path,
            loc=optional_string(table, 'loc', where),
            pwd=optional_string(table, 'pwd', where),
            desc=optional_string(table, 'desc', where),
            author=optional_string(table, 'author', where),
            groups=members,
        )
    check_no_shadowing(tuple(files))

    token_file = raw.get('token_file', DEFAULT_TOKEN_FILE)
    if not isinstance(token_file, str):
        raise SystemExit(f'{input_path} 的 token_file 须为字符串')
    return Source(users=users, groups=groups, files=files, token_file=Path(token_file))


def token_hash(token: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip('=')


def derive_key(token: str, salt: bytes) -> bytes:
    # pycryptodome 的桩把 password 标成 str；传字节串才按 UTF-8 处理，传 str 会按 Latin-1 编码。
    return PBKDF2(
        token.encode(),  # pyright: ignore[reportArgumentType]
        salt,
        dkLen=KEY_BYTES,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def pack(payload: object) -> bytes:
    '''msgpack 不带 py.typed，它的 packb 推断出的返回类型多了一个 None。'''
    return cast('bytes', msgpack.packb(payload))


def encrypt(key: bytes, nonce: bytes, payload: object) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(pack(payload))
    return ciphertext + tag


def toml_string(value: str) -> str:
    '''按 TOML 基本字符串转义，JSON 的转义规则是它的真子集。'''
    return json.dumps(value, ensure_ascii=False)


def read_tokens(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = read_toml(path)
    for name, token in raw.items():
        if not isinstance(token, str):
            raise SystemExit(f'{path} 中 {name} 的 Token 须为字符串')
    return raw


def merge_tokens(existing: dict[str, str], users: tuple[str, ...]) -> dict[str, str]:
    merged = dict(existing)
    for name in users:
        if not merged.get(name):
            merged[name] = secrets.token_urlsafe()
    seen: dict[str, str] = {}
    for name, token in merged.items():
        if token in seen:
            raise SystemExit(f'{name} 与 {seen[token]} 的 Token 相同')
        seen[token] = name
    return merged


def write_tokens(path: Path, tokens: dict[str, str]) -> None:
    path.write_text(
        ''.join(f'{toml_string(name)} = {toml_string(token)}\n' for name, token in tokens.items()),
        encoding='utf-8',
    )


def convert(input_path: Path, web_data_dir: Path) -> None:
    source = read_source(input_path)
    tokens = merge_tokens(read_tokens(source.token_file), source.users)
    defined = set(source.users)
    for name in tokens:
        if name not in defined:
            print(f'警告：{source.token_file} 中的 {name} 未定义，已保留', file=sys.stderr)

    group_slots = {name: slot for slot, name in enumerate(source.groups)}
    file_slots = {path: len(group_slots) + slot for slot, path in enumerate(source.files)}
    group_keys = {name: secrets.token_bytes(KEY_BYTES) for name in source.groups}
    file_keys = {path: secrets.token_bytes(KEY_BYTES) for path in source.files}
    shared: list[list[bytes]] = [[b'', b''] for _ in range(len(group_slots) + len(file_slots))]

    for path, spec in source.files.items():
        nonce = secrets.token_bytes(NONCE_BYTES)
        fields = (
            ('path', spec.path),
            ('loc', spec.loc),
            ('pwd', spec.pwd),
            ('desc', spec.desc),
            ('author', spec.author),
        )
        payload = {key: value for key, value in fields if value is not None}
        shared[file_slots[path]] = [nonce, encrypt(file_keys[path], nonce, payload)]

    for name in source.groups:
        nonce = secrets.token_bytes(NONCE_BYTES)
        payload = [
            [file_slots[path], file_keys[path]]
            for path, spec in source.files.items()
            if name in spec.groups
        ]
        shared[group_slots[name]] = [nonce, encrypt(group_keys[name], nonce, payload)]

    user_files: dict[str, bytes] = {}
    for name in source.users:
        token = tokens[name]
        salt = secrets.token_bytes(SALT_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        payload = {
            'name': name,
            'groups': [
                [group_slots[group], group_keys[group]]
                for group, members in source.groups.items()
                if name in members
            ],
        }
        blob = pack([salt, nonce, encrypt(derive_key(token, salt), nonce, payload)])
        user_files[token_hash(token)] = blob

    # Token 先落盘：数据文件用不到它们时也丢不了，反过来会让用户永久失去访问权。
    write_tokens(source.token_file, tokens)
    data_dir = web_data_dir / DATA_DIR
    shutil.rmtree(data_dir, ignore_errors=True)
    (data_dir / USER_DIR).mkdir(parents=True)
    for name, blob in user_files.items():
        (data_dir / USER_DIR / name).write_bytes(blob)
    (data_dir / SHARED_DATA_FILE).write_bytes(pack(shared))
    print(f'用户 {len(source.users)}，分组 {len(source.groups)}，文件 {len(source.files)}')


def download_dependencies(web_data_dir: Path) -> None:
    for relative, url in DEPENDENCIES:
        target = web_data_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:
            content = response.read()
        target.write_bytes(content)
        print(f'{relative} {len(content)} 字节')


def static_relative_path(url_path: str) -> str | None:
    '''把请求路径映射为前端数据目录里的相对路径，白名单之外的路径返回 None。'''
    path = urllib.parse.unquote(url_path.split('?', 1)[0].split('#', 1)[0])
    if '..' in path.split('/'):
        # 解码后再逐段检查，编码过的 .. 同样被拦下。
        return None
    if path.endswith('/'):
        # 只有根路径映射到 index.html，目录本身不提供。
        return INDEX_FILE if path == '/' else None
    relative = posixpath.normpath(path).lstrip('/')
    if relative == INDEX_FILE or any(relative.startswith(f'{name}/') for name in STATIC_DIRS):
        return relative
    return None


def make_handler(web_data_dir: Path) -> type[http.server.SimpleHTTPRequestHandler]:
    search_dirs = tuple(dict.fromkeys((web_data_dir.resolve(), Path.cwd())))

    class Handler(http.server.SimpleHTTPRequestHandler):
        timeout = REQUEST_TIMEOUT

        def translate_path(self, path: str) -> str:
            relative = static_relative_path(path)
            if relative is not None:
                for directory in search_dirs:
                    candidate = directory / relative
                    if candidate.is_file():
                        return str(candidate)
            # 空路径落到 send_head 的 404 分支。
            return ''

    return Handler


def run_web(address: str, port: int, web_data_dir: Path) -> None:
    if not web_data_dir.is_dir():
        raise SystemExit(f'{web_data_dir} 不是目录')
    server = http.server.ThreadingHTTPServer((address, port), make_handler(web_data_dir))
    print(f'http://{address}:{server.server_port}/')
    with server, contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


def run_data(args: argparse.Namespace, web_data_dir: Path) -> None:
    if args.update:
        download_dependencies(web_data_dir)
    if args.convert:
        convert(Path(args.convert_input or DEFAULT_INPUT), web_data_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cli.py',
        description='离线查询系统的数据准备工具与本地 HTTP 服务器',
    )
    commands = parser.add_subparsers(dest='command', required=True)

    data = commands.add_parser('data', help='准备前端数据')
    data.add_argument(
        '-u', dest='update', action='store_true', help='下载依赖到 <WEB_DATA_DIR>/lib/'
    )
    data.add_argument('-c', dest='convert', action='store_true', help='把原始数据转换为加密数据')
    data.add_argument(
        '--convert-input',
        metavar='ORIG_FILE',
        help=f'原始数据文件，默认 {DEFAULT_INPUT}',
    )
    data.add_argument(
        'web_data_dir',
        nargs='?',
        default=DEFAULT_WEB_DATA_DIR,
        metavar='WEB_DATA_DIR',
        help=f'前端数据目录，默认 {DEFAULT_WEB_DATA_DIR}',
    )

    web = commands.add_parser('web', help='启动 HTTP 服务器')
    web.add_argument('-b', dest='bind', default='127.0.0.1', metavar='ADDRESS', help='监听地址')
    web.add_argument('-p', dest='port', type=int, default=8000, metavar='PORT', help='监听端口')
    web.add_argument(
        'web_data_dir',
        nargs='?',
        default=DEFAULT_WEB_DATA_DIR,
        metavar='WEB_DATA_DIR',
        help=f'前端数据目录，默认 {DEFAULT_WEB_DATA_DIR}',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == 'data':
        if args.convert_input is not None and not args.convert:
            parser.error('--convert-input 须与 -c 一起使用')
        run_data(args, Path(args.web_data_dir))
        return 0
    if args.command == 'web':
        run_web(args.bind, args.port, Path(args.web_data_dir))
        return 0
    raise ValueError(f'未知子命令：{args.command}')


if __name__ == '__main__':
    sys.exit(main())
