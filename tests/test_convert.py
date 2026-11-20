'''数据转换的端到端检查。

密钥在这里用 hashlib 独立派生，好让 pycryptodome 的 PBKDF2 参数写错时立刻暴露，
浏览器端用 WebCrypto 复现的正是这套参数。
'''

import base64
import hashlib
import tomllib

from pathlib import Path
from typing import Any

import msgpack
import pytest

from Crypto.Cipher import AES

import cli

ALICE = 'alice-token'
BOB = 'bob-token'
SALT_BYTES = 16
TAG_BYTES = 16

SOURCE = '''\
token_file = './token.toml'

[user.alice]
[user.bob]

[group.readers]
users = ["alice", "bob"]

[group.ops]
users = ["alice"]

[[roots]]
dirs = [
    { name = 'docs', files = [
        {
            name = 'a.txt',
            loc = 'https://example.org/a',
            pwd = 'pw-a',
            desc = "第一行\\n\\n第二行",
            author = 'alice',
            groups = ["readers"],
        },
        { name = 'b.txt', groups = ["readers", "ops"] },
    ] },
    { name = 'secret', files = [
        { name = 'c.txt', pwd = 'pw-c', groups = ["ops"] },
    ] },
]
'''

INHERITANCE = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
loc = 'https://example.org'
pwd = 'shared'
groups = ["g"]
dirs = [
    { name = 'd', files = [
        { name = 'x.txt' },
        { name = 'y.txt', pwd = '', author = 'bob' },
    ] },
]
'''

VARIABLES = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
loc = 'https://example.org/'
dirs = [
    { name = 'd', loc = '${parent.loc}${name}/', files = [
        {
            name = 'a.tar.gz',
            loc = '${path}',
            pwd = '${bareName}-${parent.name}',
            desc = '$${name} 属于 ${parent.bareName}',
            groups = ["g"],
        },
    ] },
]
'''

MERGE = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
author = 'A'
groups = ["g"]
dirs = [{ name = 'd', files = [{ name = 'f1.txt' }] }]

[[roots]]
author = 'B'
groups = ["g"]
dirs = [{ name = 'd', files = [{ name = 'f2.txt' }] }]
'''

NAME_IGNORED = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
name = 'prod'
groups = ["g"]
files = [{ name = 'a.txt' }]
'''

EMPTY_ATTRIBUTES = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
groups = ["g"]
files = [{ name = 'a.txt', loc = '', pwd = '', desc = '', author = '' }]
'''

EMPTY_DIRECTORIES = '''\
[user.alice]
[group.g]
users = ["alice"]

[[roots]]
groups = ["g"]
dirs = [{ name = 'empty' }]
'''

CONFLICTING_PATH = (
    '[user.alice]\n[[roots]]\nfiles = [{ name = "a" }]\n'
    'dirs = [{ name = "a", files = [{ name = "b" }] }]\n'
)

DUPLICATE_FILE = (
    '[user.alice]\n[[roots]]\nfiles = [{ name = "a.txt" }]\n'
    '[[roots]]\nfiles = [{ name = "a.txt" }]\n'
)

TOKENS = f'"alice" = "{ALICE}"\n"bob" = "{BOB}"\n'


def token_hash(token: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).decode().rstrip('=')


def unseal(key: bytes, nonce: bytes, blob: bytes) -> Any:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return msgpack.unpackb(cipher.decrypt_and_verify(blob[:-TAG_BYTES], blob[-TAG_BYTES:]))


def derive_key(token: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', token.encode(), salt, 600_000, 32)


def read_user(web_data_dir: Path, token: str) -> dict[str, Any]:
    raw = (web_data_dir / 'data' / 'user' / token_hash(token)).read_bytes()
    salt, nonce, blob = msgpack.unpackb(raw)
    return unseal(derive_key(token, salt), nonce, blob)


def read_files(web_data_dir: Path, token: str) -> dict[str, dict[str, Any]]:
    '''按前端的顺序解开：用户文件给出分组，分组给出文件。'''
    shared: list[list[bytes]] = msgpack.unpackb((web_data_dir / 'data' / 'data').read_bytes())
    user = read_user(web_data_dir, token)
    files: dict[str, dict[str, Any]] = {}
    for group_id, group_key in user['groups']:
        nonce, blob = shared[group_id]
        for file_id, file_key in unseal(group_key, nonce, blob):
            nonce, blob = shared[file_id]
            payload = unseal(file_key, nonce, blob)
            files[payload['path']] = payload
    return files


def read_tokens(workspace: Path) -> dict[str, Any]:
    return tomllib.loads((workspace / 'token.toml').read_text(encoding='utf-8'))


def convert(workspace: Path, source: str) -> dict[str, dict[str, Any]]:
    (workspace / 'data.toml').write_text(source, encoding='utf-8')
    cli.main(['data', '-c'])
    return read_files(workspace, ALICE)


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'data.toml').write_text(SOURCE, encoding='utf-8')
    (tmp_path / 'token.toml').write_text(TOKENS, encoding='utf-8')
    return tmp_path


def test_each_user_reads_its_own_files(workspace: Path) -> None:
    assert cli.main(['data', '-c']) == 0

    assert set(read_files(workspace, ALICE)) == {'/docs/a.txt', '/docs/b.txt', '/secret/c.txt'}
    assert set(read_files(workspace, BOB)) == {'/docs/a.txt', '/docs/b.txt'}
    assert read_user(workspace, ALICE)['name'] == 'alice'


def test_file_fields_survive_the_round_trip(workspace: Path) -> None:
    cli.main(['data', '-c'])

    files = read_files(workspace, ALICE)
    assert files['/docs/a.txt'] == {
        'path': '/docs/a.txt',
        'loc': 'https://example.org/a',
        'pwd': 'pw-a',
        'desc': '第一行\n\n第二行',
        'author': 'alice',
    }
    assert files['/docs/b.txt'] == {'path': '/docs/b.txt'}


def test_existing_tokens_are_reused(workspace: Path) -> None:
    cli.main(['data', '-c'])
    first_user_file = (workspace / 'data' / 'user' / token_hash(ALICE)).read_bytes()

    cli.main(['data', '-c'])

    assert (workspace / 'token.toml').read_text(encoding='utf-8') == TOKENS
    assert (workspace / 'data' / 'user' / token_hash(ALICE)).read_bytes() != first_user_file
    assert set(read_files(workspace, ALICE)) == {'/docs/a.txt', '/docs/b.txt', '/secret/c.txt'}


def test_missing_tokens_are_generated_uniquely(workspace: Path) -> None:
    (workspace / 'token.toml').unlink()

    cli.main(['data', '-c'])

    tokens = read_tokens(workspace)
    assert set(tokens) == {'alice', 'bob'}
    assert tokens['alice'] != tokens['bob']
    assert set(read_files(workspace, tokens['bob'])) == {'/docs/a.txt', '/docs/b.txt'}


def test_undefined_token_owner_is_warned_and_kept(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (workspace / 'token.toml').write_text(f'{TOKENS}"ghost" = "ghost-token"\n', encoding='utf-8')

    cli.main(['data', '-c'])

    assert 'ghost' in capsys.readouterr().err
    assert read_tokens(workspace)['ghost'] == 'ghost-token'


def test_stale_user_files_are_removed(workspace: Path) -> None:
    stale = workspace / 'data' / 'user'
    stale.mkdir(parents=True)
    (stale / 'stale').write_bytes(b'old')

    cli.main(['data', '-c'])

    assert sorted(path.name for path in stale.iterdir()) == sorted(
        [token_hash(ALICE), token_hash(BOB)]
    )


def test_attributes_inherit_downward_and_empty_values_truncate(workspace: Path) -> None:
    files = convert(workspace, INHERITANCE)

    assert files['/d/x.txt'] == {
        'path': '/d/x.txt',
        'loc': 'https://example.org',
        'pwd': 'shared',
    }
    assert files['/d/y.txt'] == {
        'path': '/d/y.txt',
        'loc': 'https://example.org',
        'author': 'bob',
    }


def test_variables_use_resolved_parent_values(workspace: Path) -> None:
    files = convert(workspace, VARIABLES)

    assert files['/d/a.tar.gz'] == {
        'path': '/d/a.tar.gz',
        'loc': '/d/a.tar.gz',
        'pwd': 'a-d',
        'desc': '${name} 属于 d',
    }


def test_roots_merge_by_file_path_with_their_own_attributes(workspace: Path) -> None:
    files = convert(workspace, MERGE)

    assert files == {
        '/d/f1.txt': {'path': '/d/f1.txt', 'author': 'A'},
        '/d/f2.txt': {'path': '/d/f2.txt', 'author': 'B'},
    }


def test_root_name_is_ignored(workspace: Path) -> None:
    assert set(convert(workspace, NAME_IGNORED)) == {'/a.txt'}


def test_empty_declarations_are_omitted(workspace: Path) -> None:
    assert convert(workspace, EMPTY_ATTRIBUTES) == {'/a.txt': {'path': '/a.txt'}}


def test_directories_without_files_do_not_appear(workspace: Path) -> None:
    assert convert(workspace, EMPTY_DIRECTORIES) == {}


@pytest.mark.parametrize(
    ('body', 'message'),
    [
        ('[users.alice]\n', '未知字段：users'),
        ('[user]\nalice = 1\n', '须为表'),
        ('[user.alice]\n[group.g]\nusers = "alice"\n', '须为字符串数组'),
        ('[user.alice]\n[group.g]\nusers = ["ghost"]\n', '未定义的用户：ghost'),
        (
            '[user.alice]\n[[roots]]\nfiles = [{ name = "a.txt", groups = ["ghost"] }]\n',
            '未定义的分组：ghost',
        ),
        ('roots = 1\n', '须为表数组'),
        ('[[roots]]\nx = 1\n', '未知字段：x'),
        ('[[roots]]\nfiles = [{ name = "a.txt", lco = "x" }]\n', '未知字段：lco'),
        ('[[roots]]\ndirs = [{ name = "d", x = 1 }]\n', '未知字段：x'),
        ('[[roots]]\nfiles = [{ name = "a.txt", loc = 1 }]\n', 'loc 须为字符串'),
        ('[[roots]]\nfiles = [{}]\n', 'name 须为非空'),
        ('[[roots]]\nfiles = [{ name = "" }]\n', 'name 须为非空'),
        ('[[roots]]\nfiles = [{ name = "a/b" }]\n', 'name 须为非空'),
        ('[[roots]]\nfiles = [{ name = " a" }]\n', 'name 须为非空'),
        ('[[roots]]\nfiles = [{ name = "a", loc = "${nope}" }]\n', '未知变量：${nope}'),
        ('[[roots]]\nfiles = [{ name = "a", loc = "${name" }]\n', '未闭合的 ${'),
        ('[[roots]]\nloc = "${name}"\n', '未知变量：${name}'),
        (
            '[[roots]]\ndirs = [{ name = "d", loc = "${parent.name}" }]\n',
            '未知变量：${parent.name}',
        ),
        (CONFLICTING_PATH, '既是文件又是目录'),
        (DUPLICATE_FILE, '文件路径重复：/a.txt'),
    ],
)
def test_invalid_source_is_rejected(workspace: Path, body: str, message: str) -> None:
    (workspace / 'data.toml').write_text(body, encoding='utf-8')

    with pytest.raises(SystemExit) as exit_code:
        cli.main(['data', '-c'])

    assert message in str(exit_code.value)


def test_duplicate_tokens_are_rejected(workspace: Path) -> None:
    (workspace / 'token.toml').write_text('"alice" = "same"\n"bob" = "same"\n', encoding='utf-8')

    with pytest.raises(SystemExit) as exit_code:
        cli.main(['data', '-c'])

    assert 'Token 相同' in str(exit_code.value)


def test_convert_reads_the_given_file(workspace: Path) -> None:
    (workspace / 'other.toml').write_text('[user.alice]\n', encoding='utf-8')

    cli.main(['data', '-c', 'other.toml'])

    assert set(read_files(workspace, ALICE)) == set()


def test_token_file_is_resolved_next_to_the_source(workspace: Path) -> None:
    configs = workspace / 'configs'
    configs.mkdir()
    (configs / 'data.toml').write_text(SOURCE, encoding='utf-8')
    (configs / 'token.toml').write_text(TOKENS, encoding='utf-8')
    (workspace / 'token.toml').unlink()

    cli.main(['data', '-c', 'configs/data.toml', '-d', 'configs'])

    assert (configs / 'token.toml').read_text(encoding='utf-8') == TOKENS
    assert not (workspace / 'token.toml').exists()
    assert set(read_files(configs, ALICE)) == {'/docs/a.txt', '/docs/b.txt', '/secret/c.txt'}


def test_web_data_dir_is_created_and_filled(workspace: Path) -> None:
    cli.main(['data', '-c', '-d', 'build'])

    assert (workspace / 'build' / 'data' / 'data').is_file()
    assert set(read_files(workspace / 'build', BOB)) == {'/docs/a.txt', '/docs/b.txt'}
