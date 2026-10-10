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

[file."/docs/a.txt"]
loc = 'https://example.org/a'
pwd = 'pw-a'
desc = "第一行\\n\\n第二行"
author = 'alice'
groups = ["readers"]

[file."/docs/b.txt"]
groups = ["readers", "ops"]

[file."/secret/c.txt"]
pwd = 'pw-c'
groups = ["ops"]
'''

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

    tokens = tomllib.loads((workspace / 'token.toml').read_text(encoding='utf-8'))
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
    tokens = tomllib.loads((workspace / 'token.toml').read_text(encoding='utf-8'))
    assert tokens['ghost'] == 'ghost-token'


def test_stale_user_files_are_removed(workspace: Path) -> None:
    stale = workspace / 'data' / 'user'
    stale.mkdir(parents=True)
    (stale / 'stale').write_bytes(b'old')

    cli.main(['data', '-c'])

    assert sorted(path.name for path in stale.iterdir()) == sorted(
        [token_hash(ALICE), token_hash(BOB)]
    )


@pytest.mark.parametrize(
    ('body', 'message'),
    [
        (
            '[user.alice]\n[group.g]\nusers = ["ghost"]\n[file."/a.txt"]\ngroups = ["g"]\n',
            '未定义的用户：ghost',
        ),
        (
            '[user.alice]\n[group.g]\nusers = ["alice"]\n[file."/a.txt"]\ngroups = ["ghost"]\n',
            '未定义的分组：ghost',
        ),
        ('[users.alice]\n', '未知字段：users'),
        ('[user.alice]\n[group.g]\nusers = "alice"\n', '须为字符串数组'),
        ('[user]\nalice = 1\n', '须为表'),
        ('[user.alice]\n[file."a.txt"]\n', '不以 / 结尾：a.txt'),
        ('[user.alice]\n[file."/a/"]\n', '不以 / 结尾：/a/'),
        ('[user.alice]\n[file."//a"]\n', '首尾含空白：//a'),
        ('[user.alice]\n[file."/ a"]\n', '首尾含空白：/ a'),
        ('[user.alice]\n[file."/a.txt"]\nlco = "x"\n', '未知字段：lco'),
        ('[user.alice]\n[file."/a.txt"]\nloc = 1\n', 'loc 须为字符串'),
        ('[user.alice]\n[file."/a"]\n[file."/a/b"]\n', '既是文件又是目录'),
    ],
)
def test_invalid_source_is_rejected(
    workspace: Path,
    body: str,
    message: str,
) -> None:
    (workspace / 'data.toml').write_text(body, encoding='utf-8')

    with pytest.raises(SystemExit) as exit_code:
        cli.main(['data', '-c'])

    assert message in str(exit_code.value)


def test_duplicate_tokens_are_rejected(workspace: Path) -> None:
    (workspace / 'token.toml').write_text('"alice" = "same"\n"bob" = "same"\n', encoding='utf-8')

    with pytest.raises(SystemExit) as exit_code:
        cli.main(['data', '-c'])

    assert 'Token 相同' in str(exit_code.value)


def test_convert_input_requires_convert(
    workspace: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_code:
        cli.main(['data', '--convert-input', 'other.toml'])

    assert exit_code.value.code == 2
    assert '须与 -c 一起使用' in capsys.readouterr().err


def test_convert_reads_the_given_file(workspace: Path) -> None:
    (workspace / 'other.toml').write_text('[user.alice]\n', encoding='utf-8')

    cli.main(['data', '-c', '--convert-input', 'other.toml'])

    assert set(read_files(workspace, ALICE)) == set()


def test_web_data_dir_is_created_and_filled(workspace: Path) -> None:
    cli.main(['data', '-c', 'build'])

    assert (workspace / 'build' / 'data' / 'data').is_file()
    assert set(read_files(workspace / 'build', BOB)) == {'/docs/a.txt', '/docs/b.txt'}
