# FinalCombat Local Release
简单的大冲锋登录系统，包含自建的本地服务端，可实现单人模式一键进图，目前极为简陋仅供测试，后续可能(不会)进一步开发。

本目录是一个本地兼容服务端发布包，生成时间：`2026-06-08T16:41:53+0800`。

这个版本的核心目标是本地单人进图测试。它不是完整官方服务端，也不会连接外部社区中继。

## 玩家使用

1. 确认仓库根目录下有 `game.7z.001` 和 `game.7z.002` 两个分卷文件。
2. 使用 7-Zip 解压 `game.7z.001` 到当前仓库根目录。只需要解压 `.001`，7-Zip 会自动读取 `.002`。
3. 解压完成后，根目录下应出现 `game/` 文件夹，并能看到 `game\FinalCombat.exe`。
4. 安装 Python 3.10 或更高版本。启动器会优先查找 `C:\python3.13.13\python.exe`，找不到时使用系统 `PATH` 中的 `python`。
5. 双击 `FinalCombatLocalLauncher.exe`。
6. 在窗口左侧点击 `Start local single-player`。
7. 等待本地服务启动，游戏窗口会自动打开并进入单人地图。

命令行解压示例：

```powershell
& "C:\Program Files\7-Zip\7z.exe" x .\game.7z.001 -o.\
```

如果窗口直接退出，请运行 `Start_FinalCombat_Local_Debug.bat` 查看错误。常见原因是本地端口已被旧进程占用。

本地模式使用的端口：

- HTTP 认证服务：`18090`
- TCP 代理服务：`15000`
- 游戏业务 Stub：`9000`
- 频道 Stub：`9024`

## 目录结构

- `game.7z.001` / `game.7z.002`：游戏运行文件的 7-Zip 分卷压缩包
- `game/`：解压后生成的游戏运行目录
- `server_auth/`：最小 HTTP 认证服务
- `server_proxy/`：TCP 代理层 Stub
- `server_game/`：游戏层和频道层 Stub
- `protocol_assets/`：本地单人模式使用的协议资产
- `launcher/`：启动器源码和本地服务启动脚本

## 开发者接入

右侧的开发者登录栏用于连接其他自建服务端或本地调试服务端。

三个输入项含义：

- `Server IP:port`：代理层地址，例如 `127.0.0.1:15000`
- `Account`：传给客户端 `-info` 的账号
- `Password / ticket`：优先作为 HTTP 登录密码；如果服务端没有返回票据，则直接作为 `-login` 原始 ticket 使用

启动器会按顺序尝试以下 HTTP 登录 API：

```text
POST http://<host>:18090/auth/login
POST http://<host>:18090/login
POST http://<host>:<port>/auth/login
POST http://<host>:<port>/login
```

请求体为 JSON：

```json
{ "username": "<account>", "account": "<account>", "password": "<password>" }
```

响应 JSON 中只要包含以下任一字段，启动器就会把它作为 `auth_ticket`：

```text
auth_ticket
ticket
login
token
```

最终客户端启动参数格式：

```text
FinalCombat.exe -info <account> -login <ticket> -proxysvrip <host> -proxysvrport <port> -servername FinalCombat -serverid 1
```

手动启动本地单人 Stub 的示例：

```powershell
python .\launcher\start_local.py --asset-root .\protocol_assets --asset-profile singleplayer_direct --server-name FinalCombat --capture-dir=
```

