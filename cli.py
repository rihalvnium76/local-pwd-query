'''本地密码查询系统的数据准备工具与本地 HTTP 服务器。

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

from collections.abc import Mapping, Sequence
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
DEFAULT_TOKEN_FILE = 'token.toml'
DEFAULT_WEB_DATA_DIR = './'

INDEX_FILE = 'index.html'
DATA_DIR = 'data'
USER_DIR = 'user'
SHARED_DATA_FILE = 'data'

STATIC_DIRS = ('lib', DATA_DIR)

DEPENDENCIES = (
    ('lib/msgpack.min.js', 'https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js'),
)

ATTRIBUTE_KEYS = ('loc', 'pwd', 'desc', 'author')
GROUP_KEYS = frozenset({'users'})
SOURCE_KEYS = frozenset({'token_file', 'user', 'group', 'roots'})
TREE_KEYS = frozenset({'name', *ATTRIBUTE_KEYS, 'groups', 'dirs', 'files'})
FILE_KEYS = frozenset({'name', *ATTRIBUTE_KEYS, 'groups'})


@dataclass(frozen=True, slots=True)
class Attributes:
    loc: str = ''
    pwd: str = ''
    desc: str = ''
    author: str = ''
    groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Node:
    path: str
    name: str | None
    attributes: Attributes


@dataclass(frozen=True, slots=True)
class Source:
    users: tuple[str, ...]
    groups: dict[str, tuple[str, ...]]
    files: dict[str, Attributes]
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


def table_array(value: object, where: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SystemExit(f'{where} 须为表数组')
    return [table_of(item, f'{where}[{index}]') for index, item in enumerate(value)]


def string_tuple(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f'{where} 须为字符串数组')
    return tuple(value)


def check_keys(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise SystemExit(f'{where} 出现未知字段：{"、".join(unknown)}')


def bare_name(name: str) -> str:
    dot = name.find('.', 1)
    return name if dot < 0 else name[:dot]


def expand(text: str, variables: Mapping[str, str], where: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith('$${', index):
            parts.append('${')
            index += 3
        elif text.startswith('${', index):
            end = text.find('}', index + 2)
            if end < 0:
                raise SystemExit(f'{where} 有未闭合的 ${{：{text}')
            variable = text[index + 2 : end]
            if variable not in variables:
                raise SystemExit(f'{where} 引用未知变量：${{{variable}}}')
            parts.append(variables[variable])
            index = end + 1
        else:
            parts.append(text[index])
            index += 1
    return ''.join(parts)


def resolve_attribute(
    table: dict[str, Any],
    key: str,
    inherited: str,
    variables: Mapping[str, str],
    where: str,
) -> str:
    if key not in table:
        return inherited
    value = table[key]
    if not isinstance(value, str):
        raise SystemExit(f'{where} 的 {key} 须为字符串')
    return expand(value, variables, f'{where} 的 {key}')


def resolve_groups(
    table: dict[str, Any],
    inherited: tuple[str, ...],
    groups: Mapping[str, tuple[str, ...]],
    where: str,
) -> tuple[str, ...]:
    if 'groups' not in table:
        return inherited
    members = string_tuple(table['groups'], f'{where} 的 groups')
    for member in members:
        if member not in groups:
            raise SystemExit(f'{where} 引用了未定义的分组：{member}')
    return members


def resolve_attributes(
    table: dict[str, Any],
    where: str,
    inherited: Attributes,
    variables: Mapping[str, str],
    groups: Mapping[str, tuple[str, ...]],
) -> Attributes:
    return Attributes(
        loc=resolve_attribute(table, 'loc', inherited.loc, variables, where),
        pwd=resolve_attribute(table, 'pwd', inherited.pwd, variables, where),
        desc=resolve_attribute(table, 'desc', inherited.desc, variables, where),
        author=resolve_attribute(table, 'author', inherited.author, variables, where),
        groups=resolve_groups(table, inherited.groups, groups, where),
    )


def child_variables(path: str, name: str, parent: Node) -> dict[str, str]:
    variables = {
        'path': path,
        'name': name,
        'bareName': bare_name(name),
        'parent.path': parent.path,
        'parent.loc': parent.attributes.loc,
        'parent.pwd': parent.attributes.pwd,
        'parent.desc': parent.attributes.desc,
        'parent.author': parent.attributes.author,
    }
    if parent.name is not None:
        variables['parent.name'] = parent.name
        variables['parent.bareName'] = bare_name(parent.name)
    return variables


def make_node(
    parent: Node,
    table: dict[str, Any],
    where: str,
    groups: Mapping[str, tuple[str, ...]],
    *,
    directory: bool,
) -> Node:
    check_keys(table, TREE_KEYS if directory else FILE_KEYS, where)
    name = table.get('name')
    if not isinstance(name, str) or not name or '/' in name or name != name.strip():
        raise SystemExit(f'{where} 的 name 须为非空、不含 / 且首尾没有空白的字符串')
    path = f'{parent.path}{name}{"/" if directory else ""}'
    variables = child_variables(path, name, parent)
    attributes = resolve_attributes(table, where, parent.attributes, variables, groups)
    return Node(path=path, name=name, attributes=attributes)


def walk(
    node: Node,
    table: dict[str, Any],
    where: str,
    groups: Mapping[str, tuple[str, ...]],
    files: dict[str, Attributes],
) -> None:
    for index, dir_table in enumerate(table_array(table.get('dirs'), f'{where} 的 dirs')):
        child_where = f'{where} 的 dirs[{index}]'
        child = make_node(node, dir_table, child_where, groups, directory=True)
        walk(child, dir_table, child_where, groups, files)
    for index, file_table in enumerate(table_array(table.get('files'), f'{where} 的 files')):
        child_where = f'{where} 的 files[{index}]'
        child = make_node(node, file_table, child_where, groups, directory=False)
        if child.path in files:
            raise SystemExit(f'{child_where} 的文件路径重复：{child.path}')
        files[child.path] = child.attributes


def collect_files(
    tree: dict[str, Any],
    index: int,
    groups: Mapping[str, tuple[str, ...]],
    files: dict[str, Attributes],
) -> None:
    where = f'roots[{index}]'
    check_keys(tree, TREE_KEYS, where)
    root = Node(
        path='/',
        name=None,
        attributes=resolve_attributes(tree, where, Attributes(), {'path': '/'}, groups),
    )
    walk(root, tree, where, groups, files)


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

    files: dict[str, Attributes] = {}
    for index, tree in enumerate(table_array(raw.get('roots'), 'roots')):
        collect_files(tree, index, groups, files)
    check_no_shadowing(tuple(files))

    token_file = raw.get('token_file', DEFAULT_TOKEN_FILE)
    if not isinstance(token_file, str):
        raise SystemExit(f'{input_path} 的 token_file 须为字符串')
    token_path = Path(token_file)
    if not token_path.is_absolute():
        token_path = input_path.parent / token_path
    return Source(users=users, groups=groups, files=files, token_file=token_path)


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

    for path, attributes in source.files.items():
        nonce = secrets.token_bytes(NONCE_BYTES)
        fields = (
            ('path', path),
            ('loc', attributes.loc),
            ('pwd', attributes.pwd),
            ('desc', attributes.desc),
            ('author', attributes.author),
        )
        payload = {key: value for key, value in fields if value}
        shared[file_slots[path]] = [nonce, encrypt(file_keys[path], nonce, payload)]

    for name in source.groups:
        nonce = secrets.token_bytes(NONCE_BYTES)
        payload = [
            [file_slots[path], file_keys[path]]
            for path, attributes in source.files.items()
            if name in attributes.groups
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
    if args.convert is not None:
        convert(Path(args.convert), web_data_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cli.py',
        description='本地密码查询系统的数据准备工具与本地 HTTP 服务器',
    )
    commands = parser.add_subparsers(dest='command', required=True)

    data = commands.add_parser('data', help='准备前端数据')
    data.add_argument(
        '-u', dest='update', action='store_true', help='下载依赖到 <WEB_DATA_DIR>/lib/'
    )
    data.add_argument(
        '-c',
        dest='convert',
        nargs='?',
        const=DEFAULT_INPUT,
        metavar='ORIG_FILE',
        help=f'把原始数据转换为加密数据，默认 {DEFAULT_INPUT}',
    )
    data.add_argument(
        '-d',
        dest='web_data_dir',
        default=DEFAULT_WEB_DATA_DIR,
        metavar='WEB_DATA_DIR',
        help=f'前端数据目录，默认 {DEFAULT_WEB_DATA_DIR}',
    )

    web = commands.add_parser('web', help='启动 HTTP 服务器')
    web.add_argument('-b', dest='bind', default='127.0.0.1', metavar='ADDRESS', help='监听地址')
    web.add_argument('-p', dest='port', type=int, default=8000, metavar='PORT', help='监听端口')
    web.add_argument(
        '-d',
        dest='web_data_dir',
        default=DEFAULT_WEB_DATA_DIR,
        metavar='WEB_DATA_DIR',
        help=f'前端数据目录，默认 {DEFAULT_WEB_DATA_DIR}',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == 'data':
        run_data(args, Path(args.web_data_dir))
        return 0
    if args.command == 'web':
        run_web(args.bind, args.port, Path(args.web_data_dir))
        return 0
    raise ValueError(f'未知子命令：{args.command}')


if __name__ == '__main__':
    sys.exit(main())
