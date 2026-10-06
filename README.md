# localPwdQuery

离线加密查询系统的实现。数据格式、页面行为与命令参数由 `DESIGN.md` 定义，这里只说明目录里有什么、怎么跑起来。

## 目录

- `index.html`：前端单页，样式与脚本都内联在其中
- `cli.py`：`data` 子命令准备前端数据，`web` 子命令起本地 HTTP 服务器
- `pyproject.toml`：依赖、ruff、pyright、pytest 的配置
- `tests/`：数据转换与 web 路由的检查
- `data.toml`、`token.toml`：管理员持有的明文源数据与 Token 清单
- `lib/`、`data/`、`version`：`cli.py` 生成的前端数据

后四项由 `.gitignore` 排除，仓库里只有工具与页面源码。后端要求 Python 3.11+。

## 本地运行

```sh
uv sync
uv run cli.py data -u -c     # 下载 msgpack，把 ./data.toml 转成 ./data/
uv run cli.py web            # 默认 http://127.0.0.1:8000/
```

`data -c` 首次运行会生成 Token 并写进 `token.toml`，用其中的 Token 在页面上登录。Token 与密码生成都依赖 WebCrypto，页面需要通过 `localhost` 或 HTTPS 打开。

## 部署

发布目录里的 `index.html`、`version`、`lib/`、`data/` 由浏览器按相对路径加载，必须同处一个目录。发布时把它们生成到站点目录再提交：

```sh
uv run cli.py data -u -c 站点目录
```

## 验证

```sh
uv run pytest
uv run ruff check
uv run pyright
```
