'''web 子命令的路由检查，用真实的 HTTP 连接发出请求。'''

import http.client
import http.server
import threading

from collections.abc import Iterator
from pathlib import Path

import pytest

import cli

INDEX = '<html>web</html>'


@pytest.fixture
def server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[http.server.ThreadingHTTPServer]:
    web = tmp_path / 'web'
    (web / 'lib').mkdir(parents=True)
    (web / 'index.html').write_text(INDEX, encoding='utf-8')
    (web / 'lib' / 'msgpack.min.js').write_text('lib', encoding='utf-8')

    work = tmp_path / 'work'
    (work / 'lib').mkdir(parents=True)
    (work / 'data' / 'user').mkdir(parents=True)
    (work / 'index.html').write_text('<html>work</html>', encoding='utf-8')
    (work / 'lib' / 'msgpack.min.js').write_text('work-lib', encoding='utf-8')
    (work / 'data' / 'data').write_bytes(b'shared')
    (work / 'data' / 'user' / 'abc').write_bytes(b'user')
    (work / 'cli.py').write_text('secret', encoding='utf-8')
    monkeypatch.chdir(work)

    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), cli.make_handler(web))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    thread.join()
    httpd.server_close()


def fetch(
    server: http.server.ThreadingHTTPServer, path: str, method: str = 'GET'
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection('127.0.0.1', server.server_port)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_root_and_index_come_from_the_data_dir(server: http.server.ThreadingHTTPServer) -> None:
    assert fetch(server, '/') == (200, INDEX.encode())
    assert fetch(server, '/index.html') == (200, INDEX.encode())


def test_assets_come_from_the_data_dir_first(server: http.server.ThreadingHTTPServer) -> None:
    assert fetch(server, '/lib/msgpack.min.js') == (200, b'lib')


def test_missing_files_fall_back_to_the_working_directory(
    server: http.server.ThreadingHTTPServer,
) -> None:
    assert fetch(server, '/data/data') == (200, b'shared')
    assert fetch(server, '/data/user/abc') == (200, b'user')


def test_query_parameters_are_ignored(server: http.server.ThreadingHTTPServer) -> None:
    assert fetch(server, '/data/data?x=1') == (200, b'shared')


def test_head_returns_no_body(server: http.server.ThreadingHTTPServer) -> None:
    assert fetch(server, '/index.html', 'HEAD') == (200, b'')


@pytest.mark.parametrize(
    'path',
    [
        '/cli.py',
        '/DESIGN.md',
        '/../cli.py',
        '/lib/../index.html',
        '/data/../../cli.py',
        '/lib/',
        '/lib',
        '/data/',
        '/data',
        '/data/user',
        '/data/nope',
    ],
)
def test_paths_outside_the_whitelist_are_not_found(
    server: http.server.ThreadingHTTPServer,
    path: str,
) -> None:
    assert fetch(server, path)[0] == 404


def test_web_requires_an_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit_code:
        cli.run_web('127.0.0.1', 0, tmp_path / 'nope')

    assert '不是目录' in str(exit_code.value)
