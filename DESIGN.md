# 离线查询系统

## 概述
- 系统目标：提供纯前端、离线部署（通过本地 HTTP 服务器）的加密数据查询页面，配套 Python 脚本用于数据准备
- 组成：
    - 前端：`index.html`（单页应用）
    - 后端工具：`cli.py`（CLI 脚本）
- 技术选型：
    - 前端：原生 JavaScript + MessagePack 库（UMD）
    - 后端：Python 3.11+ 及其标准库（argparse、tomllib、http.server） + pycryptodome + msgpack

## 安全与加密机制
### 加密算法参数
- Token 生成：`secrets.token_urlsafe()`
- 密钥派生：PBKDF2‑HMAC‑SHA‑256（盐长 16 字节，迭代 600 000 次，输出 32 字节）
- 数据加密：AES‑256‑GCM（Nonce 12 字节，Tag 16 字节）
- 盐、Nonce、非派生密钥生成：`secrets.token_bytes()`

### 数据加密层级
- 用户文件：`data/user/{tokenHash}`（盐 + Nonce + 密文+Tag）
- 共享数据文件：`data/data`（数组，每个元素为 Nonce + 密文+Tag，数组下标即 ID）
- 密钥管理：用户密钥派生自 Token；分组密钥和文件密钥由工具随机生成并加密存储

## 数据规范
### 虚拟路径规范
- 以 `/` 开头，目录以 `/` 结尾，文件不能以 `/` 结尾
- 目录与文件在同一路径下不可重名
- 名称非空，首尾不含空白字符（ANSI 和 Unicode）
- 大小写敏感

### 文件存储格式（MessagePack）
- **用户文件**：`[salt (bin), nonce (bin), ciphertext+tag (bin)]`
- **共享数据文件**：`[ [nonce, ciphertext+tag], … ]`，数组下标即 ID
- 解密后的结构：
    - `user`：`{"name": str, "groups": [[groupId, groupKey], ...]}`
    - `group`：`[[fileId, fileKey], ...]`
    - `file`：`{"path": str, "loc": str?, "pwd": str?, "desc": str?, "author": str?}`

## 前端：离线查询页面（index.html）
### 文件与目录结构
- `index.html`（主页面）
- `lib/`（第三方依赖）
    - `msgpack.min.js`（MessagePack，**全局导入对象名为 `MessagePack`**）
- `data/`（数据文件，由后端工具生成）

### 页面生命周期
#### 初始化
- 加载 `msgpack.min.js`
- 读取 `data/data`，计算 SHA‑256 并转为 Base64，存入 `dataHash`；同时反序列化
- 以上步骤失败则禁止登录
- 检查 `localStorage` 中的 Token，自动尝试登录

#### 登录流程
- 用户输入 Token → 计算 `tokenHash = urlsafe_base64_nopadding(sha256(utf8_bytes(token)))`
- 读取 `data/user/{tokenHash}`，提取盐、Nonce、密文
- PBKDF2 对 `utf8_bytes(token)` 派生密钥 → AES‑GCM 解密得到 `user` 对象
- 遍历 `user.groups`，用分组密钥解密 `data` 中的分组（`group` 对象），再从分组递归解密出文件（`file` 对象），构建虚拟路径树
- 登录成功 → 存储 Token 到 `localStorage`，显示根目录；失败则提示错误
    - 登录成功但无文件展示要提示“暂无可访问的资源”

#### 并行解密优化
- 分批并行解密分组和文件（每 2 秒更新进度）

#### 加载与缓存
- 使用 `fetch()` 自动加载固定路径的本地文件（第三方依赖和数据文件）
- 数据文件禁止缓存

### UI 设计与交互
#### 布局
- 紧凑风格，适配桌面和移动端

#### 功能区域与交互规范
- **实用工具区**：“密码生成”按钮（弹出模态框）
- **Token 输入区**：Token 输入框 + 登录/注销按钮 + 用户名
- **提示信息区**：显示状态、错误或搜索结果数统计
- **搜索区**：搜索目标下拉框（“全部”、“精准路径”，表格各列）+ 搜索范围下拉框（全部、当前目录、当前及子目录）+ 搜索类型下拉框（全部、文件、目录）+ 搜索框 + 搜索按钮
    - 默认模糊匹配；搜索内容为空，或点击搜索结果中的目录时，退出搜索状态
    - 精确路径：匹配去除首尾 `/` 后完全相等的路径，仅有 `/` 则固定特殊匹配根目录本身
    - 搜索状态下隐藏导航区
- **面包屑导航区**：“上一级”“根目录”按钮 + 当前路径
    - 路径：各级可点击跳转，末级点击复制路径；显示格式 `/ 目录1 / 目录2 /`，`/` 与目录之间有空格
- **文件表格**：
    - 列：名称（`path` 解析出）、位置（`loc`）、密码（`pwd`）、描述（`desc` 解析出）、作者（`author`）
        - 名称：文件点击复制虚拟路径；目录点击进入，名字以 `/` 结尾
        - 位置/作者：点击复制
        - 描述：显示首行非空内容 + “...”（若后续存在内容），点击弹出模态框显示完整描述并支持复制
            - 描述截取实现参考：`const nonEmptyLines = (fullDesc == null ? '' : fullDesc).split('\n').map(line => line.trim()).filter(line => line); const displayDesc = (nonEmptyLines[0] || '') + (nonEmptyLines.length > 1 ? '...' : '')`
    - 排序：目录在前，按名称长度升序、再按名称升序
    - 表格支持水平滚动
    - 支持分页，包括搜索结果；分页组件：上一页按钮、页码输入框、总页数提示、下一页按钮、跳转按钮、分页大小输入框（默认 100，非正数显示全部）
- **数据校验码区**：底部显示 `dataHash`（灰色）

#### 部分组件样式与交互
- 密码（文件表格和密码生成表格的）带背景色 `#EBEEF2`、背景圆角半径 6px，支持点击复制、手选复制，始终完整显示
- 可点击复制的组件，其 Clipboard API 可能成功但无效，允许手动选择复制补救
- 搜索区、面包屑导航区、文件表格只有登录成功才显示

### 实用工具：批量密码生成模态框
- 参数：密码字节数（默认 32）、生成数量（默认 10）
- 生成类似 `secrets.token_urlsafe()` 的密码，输出到表格（序号 + 密码）
- 密码可重复复制，复制后添加删除线（仅添加一次，标记已使用）

## 后端工具（cli.py）
### 功能概述
- `data`：数据准备
  - 下载/更新前端依赖库（`-u`）
  - 转换 TOML 原始数据为加密二进制文件（`-c`）
  - 以上功能可同时使用
- `web`：启动 HTTP/1.1 服务器

### 命令结构
```
cli.py data [-u] [-c [--convert-input <ORIG_FILE>]] [WEB_DATA_DIR]
cli.py web [-b <ADDRESS>] [-p <PORT>] [WEB_DATA_DIR]
```

- `WEB_DATA_DIR`：含有或存放 `lib/`、`data/` 的前端数据目录，该目录可以不包含前端页面本身，默认 `./`

### `data` 子命令参数
| 参数 | 说明 |
|---|---|
| `-u` | 下载依赖到 `<WEB_DATA_DIR>/lib/` |
| `-c [--convert-input <ORIG_FILE>]` | 转换数据（`ORIG_FILE`，默认 `./data.toml`）到 `<WEB_DATA_DIR>/data/`。静默重建 `data/`（**重建不包含 `<WEB_DATA_DIR>/` 和它的其他子目录**）。单独指定 `--convert-input` 而不指定 `-c` 则报错 |
| `[WEB_DATA_DIR]` | 前端数据目录，默认 `./`（见公共定义） |

- 若目录不存在则递归创建

### `web` 子命令参数
| 参数 | 说明 |
|---|---|
| `-b <ADDRESS>` | 绑定监听地址（默认 `127.0.0.1`） |
| `-p <PORT>` | 监听端口（默认 `8000`） |
| `[WEB_DATA_DIR]` | 前端数据目录，默认 `./`（见公共定义） |

- 启动 HTTP/1.1 服务器
    - 请求 `/` 等价于请求 `/index.html`，并按下列规则查找
    - 先从 `<WEB_DATA_DIR>` 查找文件并返回；未命中时，再从当前工作目录查找并返回；两处均未命中时返回 `404`
    - 拒绝包含 `..` 的路径穿越请求（在 URL 解码和路径规范化后检查）

### 依赖列表（`data -u`）
| 本地路径 | 下载地址 |
| --- | --- |
| `<WEB_DATA_DIR>/lib/msgpack.min.js` | `https://unpkg.com/@msgpack/msgpack/dist.umd/msgpack.min.js` |

### 数据转换流程
#### 输入：原始数据文件（data.toml）
- 结构：
    - `token_file`（可选，指向 Token 清单文件，默认 `./token.toml`）
    - `[user."<userName>"]`（空表）
    - `[group."<groupName>"]` + `users = ["<userName>"]`
    - `[file."<virtualFilePath>"]` + `loc`, `pwd`, `desc`, `author`, `groups = ["<groupName>"]`
- 约束：
    - group 引用的 user 必须已定义
    - file 引用的 group 必须已定义
    - virtualFilePath 遵守虚拟路径规范

#### 处理步骤
1. 读取并校验 TOML，构建依赖关系图
2. 为每个 user 分配盐和 Nonce，为每个 group 和 file 分配唯一 ID（即 `data` 数组下标）、Nonce 和密钥
3. 读取/生成 Token 清单（`token.toml`）：
    - 若用户已有 Token 则复用，否则生成新 Token 并写入清单
    - 检查 Token 唯一性，警告未定义用户
4. 加密各对象：
    - user：使用 Token 派生密钥加密 → 写入 `data/user/{tokenHash}`
    - group/file：使用各自密钥加密 → 存入 `data/data` 对应下标位置
5. 输出统计信息（已处理的用户数、分组数、文件数等）

#### 输出文件
- `data/user/{tokenHash}`（每个用户一个文件）
- `data/data`（共享数据数组）
- `token.toml`（更新后的 Token 清单）

#### 实现注意事项
- `Crypto.Protocol.KDF.PBKDF2` 的 `hmac_hash_module` 参数要使用 `Crypto.Hash` 下的实现（如 `Crypto.Hash.SHA256`），不能省略或使用 hashlib 中的构造器

### Token 清单文件（token.toml）
- 格式：`"<userName>" = "<token>"`
- 工具自动维护，管理员可查看
- 约束：不同用户的 Token 不可重复
