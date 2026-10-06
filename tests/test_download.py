'''data -u 的下载检查，用本地 HTTP 服务器替代外网。'''

import http.server
import threading

from collections.abc import Iterator
from pathlib import Path

import pytest

import cli

CONTENT = b'globalThis.MessagePack = {};'


@pytest.fixture
def origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    origin_dir = tmp_path / 'origin'
    origin_dir.mkdir()
    (origin_dir / 'msgpack.min.js').write_bytes(CONTENT)
    monkeypatch.chdir(origin_dir)

    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{httpd.server_port}/msgpack.min.js'
    httpd.shutdown()
    thread.join()
    httpd.server_close()


def test_dependencies_are_downloaded(
    origin: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, 'DEPENDENCIES', (('lib/msgpack.min.js', origin),))

    assert cli.main(['data', '-u', str(tmp_path / 'build')]) == 0

    assert (tmp_path / 'build' / 'lib' / 'msgpack.min.js').read_bytes() == CONTENT
    assert (tmp_path / 'build' / 'version').is_file()
