# CTF Blackboard

**比赛期间，队里所有“谁解了、谁占了、写到哪了”都在一块黑板上。**

[![release](https://img.shields.io/github/v/release/guaidao2/ctf-blackboard?color=5ee6b0&label=release&cacheSeconds=3600)](https://github.com/guaidao2/ctf-blackboard/releases)
[![license](https://img.shields.io/github/license/guaidao2/ctf-blackboard?color=5ee6b0)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/guaidao2/ctf-blackboard?color=5ee6b0)](go.mod)

CTF Blackboard 是给 CTF 队伍用的实时协同黑板。服务端一条命令启动，队员用本地 GUI 登录，共享战果、容器位、writeup 和聊天。

- **单密码**：全队一个密码，昵称自己填。
- **通信加密**：TLS 1.3 + 首次信任指纹 + 每会话 AES-256-GCM。
- **零平台依赖**：不拉 Docker、不对接 CTFd/rCTF，不依赖数据库。
- **单文件分发**：服务端和客户端各一个二进制，前端资源已内嵌。

## 为什么需要它

比赛中最常见的三个问题：

- 谁交了哪道题的 flag，散在群聊里，过一会儿就找不到。
- 比赛平台限制容器数量，开一个新的可能把别人的顶掉。
- writeup 东一份西一份，赛后想整理却拼不起来。

黑板只做这三件事，并把它们放在所有人随时能看到的地方。

## 功能

### 战果墙

记录“最终是谁交了这道题的 flag”。

- 题目名、解题人、writeup、记录时间。
- 多人同题只记最终提交人，不搞内部排名。
- writeup 可以直接写，也可以先空着后补。
- 支持搜索、编辑、删除。
- 一键导出全部 writeup 为 Markdown。

### 容器位

记录“哪道题、谁占的、地址/端口、备注、占了多久”。

- 服务端设置总上限；占用时如果已满，直接拒绝。
- 拒绝时会列出当前每个位是谁占的、占的哪题。
- 必须先释放一个，才能再开下一个，避免把别人的容器顶掉。
- 释放后进入历史记录。

### 团队频道

- 全队一个频道，战果、容器位、踢人自动播报。
- 页面在后台、窗口失焦、或不在聊天页时，新消息会播放提示音。
- 未读数显示在聊天标签和浏览器标题；右上角可静音。

### 随时可调

比赛是动态的：

- 题目总数随时改，新上题直接加。
- 容器位上限随时改，立即生效。
- 公告随时改。

### 安全连接

- 首次连接像 SSH 一样显示 SHA-256 指纹，确认后才发送密码。
- 确认后记住指纹，下次自动校验；指纹变化会拒绝连接。
- 密码只做挑战应答，不在网络上传输。
- 登录后的每一帧再用每会话独立的 AES-256-GCM 加密。

### 轻量部署

- 服务端无 GUI、无数据库，适合 systemd 常驻。
- 客户端在 `127.0.0.1` 启动本地 GUI，自动打开浏览器。
- 状态原子落盘并保留上一版备份。

## 快速开始

### 1. 获取

从 [Releases](https://github.com/guaidao2/ctf-blackboard/releases) 下载对应平台压缩包，或者从源码构建：

```bash
go build -o bin/ctfbb-server ./cmd/ctfbb-server
go build -o bin/ctfbb-client ./cmd/ctfbb-client
```

### 2. 启动服务端

```bash
export CTFBB_PASSWORD='换成一串至少 12 位的共享密码'
./bin/ctfbb-server \
  --listen 0.0.0.0:8443 \
  --data ./data \
  --slots 5 \
  --total 20 \
  --name '队内黑板'
```

首次启动会生成：

- `data/server-info.txt`：给队员的连接信息（地址 + 指纹）
- `data/state.json`：战果、容器位、聊天、动态
- `data/server.crt` / `data/server.key`：自签 TLS 证书

把 `server-info.txt`、客户端和密码发给队员。**不要发 `server.key`。**

### 3. 启动客户端

```bash
./bin/ctfbb-client --nick alice
```

登录页填服务器地址、昵称、共享密码。第一次连接会弹出指纹确认；确认后不再询问。

如果 `server-info.txt` 和客户端放在同一目录，客户端会自动读取，连指纹确认都省掉。也可以在登录页点“导入 server-info.txt”选择文件。

### 4. 开赛

- 战果墙 → `+ 记录战果`
- 容器位 → `+ 占用容器位`
- 设置 → 题目总数 / 容器位上限
- 右上角 → 导出 writeup

## 一场比赛怎么用

1. **开赛前**：服务端起好，把客户端和 `server-info.txt` 发到群里，队员登录。
2. **开容器**：谁要开实例，先在容器位里占一个，写清题目和地址；满了就找占用者协调释放。
3. **交题**：谁最终交了 flag，就在战果墙记一条；writeup 可以赛后补。
4. **赛后**：点“导出 writeup”，得到一份按题目整理的 Markdown。

## 安全说明

- 通信使用 TLS 1.3；证书是自签的，客户端通过**首次信任 + known_hosts**校验，类似 SSH。
- 也可以把服务端生成的 `server-info.txt` 发给队员，作为带外固定指纹的快捷方式。
- 密码使用 PBKDF2-HMAC-SHA256 挑战应答，服务端和客户端互相证明，密码不上网。
- 登录后每条消息使用方向独立的 AES-256-GCM 密钥加密，序号防重放。
- 单密码模式意味着**全员同权**：每个人都能记战果、开/释放容器位、改设置、踢人。适合信任的队内环境。
- 状态库 `state.json` 是**明文**，按设计只加密通信；请限制数据目录权限，不要把 `data/` 提交到 Git 或公开网盘。

更细的协议和加密流程见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

## 文档

- [部署与运维](docs/OPERATIONS.md)：参数、systemd、数据目录、备份、known_hosts。
- [协议与加密](docs/PROTOCOL.md)：握手、帧格式、命令和事件。
- [Release Notes 模板](docs/RELEASE_NOTES_TEMPLATE.md)：发布说明格式。

## 开发

```bash
go test ./...
go vet ./...
node --check internal/client/web/app.js
```

需要 Go 1.26+。前端是原生 HTML/CSS/JS，通过 `go:embed` 打进客户端。

## License

MIT © 2026 **guaidao2 & coolmoon**
