# localPwdQuery

离线加密查询系统的参考实现。数据格式、页面行为与命令参数由 `DESIGN.md` 定义；本文档仅说明目录结构与运行方式。

## 目录

- `index.html`：前端单页，样式与脚本都内联在其中
- `cli.py`：`data` 子命令准备前端数据，`web` 子命令起本地 HTTP 服务器
- `gen_bulk_data.py`：往 `data.toml` 追加一段压测条目，供页面上试用大数据量
- `pyproject.toml`：依赖、ruff、pyright、pytest 的配置
- `tests/`：数据转换、web 路由与页面交互的检查
- `data.toml`、`token.toml`：管理员持有的明文源数据与 Token 清单
- `lib/`、`data/`、`version`：`cli.py` 生成的前端数据

后四项由 `.gitignore` 排除，仓库里只有工具与页面源码。命令行工具要求 Python 3.11+。

## 本地运行

```sh
uv sync
uv run cli.py data -u -c     # 下载 msgpack，把 ./data.toml 转成 ./data/
uv run cli.py web            # 默认 http://127.0.0.1:8000/
```

`data -c` 首次运行会生成 Token 并写进 `token.toml`，用其中的 Token 在页面上登录。Token 与密码生成都依赖 WebCrypto，页面需要通过 `localhost` 或 HTTPS 打开。

## 大数据量试用

`gen_bulk_data.py` 在 `data.toml` 末尾追加一段压测条目，上一次生成的整段会被替换掉。条目总数、虚拟根目录、所属分组、目录形状都由命令行参数控制，完整参数见 `uv run gen_bulk_data.py --help`：

```sh
uv run gen_bulk_data.py --count 10000 --dirs 50 --depth 1   # 10000 条，分到 50 个目录
uv run gen_bulk_data.py --count 5000 --dirs 10 --depth 2    # 两级目录共 100 个，每个 50 条
uv run cli.py data -c                                       # 生成完重新转换一次数据
```

不带参数时是 3200 条直接放在 `/压测/` 下。

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
node tests/page_check.js
```

`tests/page_check.js` 用桩 DOM 执行 `index.html` 的内联脚本，覆盖键盘提交与分页联动这类 pytest 看不到的交互，需要本机有 Node。
