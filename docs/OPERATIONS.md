# 部署与运维

## 服务端参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--listen` | `0.0.0.0:8443` | 监听地址 |
| `--data` | `./data` | 数据目录 |
| `--password` | 空 | 共享密码（不推荐，进程列表可见） |
| `--password-file` | 空 | 从文件读取密码 |
| `--name` | `CTF Blackboard` | 黑板名称 |
| `--motd` | 默认公告 | 首次启动公告，之后可在 GUI 改 |
| `--slots` | `5` | 首次启动的容器位上限 |
| `--total` | `0` | 首次启动的题目总数 |
| `--public-url` | 自动推导 | 写进 `server-info.txt` 的地址，例如 `wss://ctf.example.com:8443/ws` |
| `--cert` / `--key` | 自动生成 | 自定义 TLS 证书/私钥 |
| `--version` | | 打印版本 |

密码优先级：`--password` > `--password-file` > `CTFBB_PASSWORD` > 交互输入。

`--slots` / `--total` 只作为**首次启动**的默认值。比赛开始后以 GUI 设置为准；这样服务端重启不会把动态调整过的上限重置。

## 客户端参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--server-info` | 自动查找 | 读取 `server-info.txt` 预填地址/指纹；默认在当前目录、`data/`、客户端同目录查找 |
| `--known-hosts` | 用户配置目录 | 指纹记忆文件路径，默认 `ctfbb/known_hosts.json` |
| `--server` | 空 | 预填 WSS 地址 |
| `--pin` | 空 | 高级：预填证书指纹（正常不需要） |
| `--allow-remote-ui` | `false` | 允许 GUI 绑定非回环地址（不推荐；默认拒绝） |
| `--nick` | 空 | 预填昵称 |
| `--listen` | `127.0.0.1:0` | 本地 GUI 监听地址 |
| `--no-open` | `false` | 不自动打开浏览器 |
| `--version` | | 打印版本 |

## 数据目录

| 文件 | 用途 |
| --- | --- |
| `state.json` | 战果、容器位、聊天、动态（明文，0600） |
| `state.json.bak` | 上一版状态备份 |
| `server.crt` / `server.key` | 自签 TLS 证书/私钥 |
| `server-info.txt` | 给队员的连接信息：`url=` + `pin=` |

启动时如果主状态文件损坏或版本不支持，会尝试从 `state.json.bak` 恢复，并把损坏文件保留为 `state.corrupt-<时间戳>.json`。

## systemd

```ini
[Unit]
Description=CTF Blackboard server
After=network-online.target

[Service]
User=ctfbb
Group=ctfbb
EnvironmentFile=/etc/ctfbb.env
ExecStart=/opt/ctfbb/ctfbb-server --listen 0.0.0.0:8443 --data /var/lib/ctfbb
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ctfbb

[Install]
WantedBy=multi-user.target
```

`/etc/ctfbb.env`：

```bash
CTFBB_PASSWORD=换成一串至少 12 位的共享密码
```

## 反向代理 / NAT

服务端直接提供 WSS，不需要 Nginx。如果前面有反向代理：

- 必须支持 WebSocket upgrade；
- 客户端地址写代理后的 `wss://.../ws`；
- 用 `--public-url` 让 `server-info.txt` 写正确的外部地址；
- 证书固定的是代理返回的证书，不是后端自签证书。

## 证书与 known_hosts

- 首次连接：客户端显示 SHA-256 指纹，确认后写入 `known_hosts.json`。
- 后续连接：自动用记住的指纹校验；不一致会拒绝连接。
- 正常换证：先删除对应条目，再用 `server-info.txt` 或“高级”里的新指纹重新登录；如果旧条目还在，客户端会拒绝覆盖，避免静默接受新证书。
- `server-info.txt` 是带外固定指纹的快捷方式；没有它也能用。

known_hosts 默认位置：

- Windows：`%AppData%\ctfbb\known_hosts.json`
- Linux/macOS：`<用户配置目录>/ctfbb/known_hosts.json`

可以用 `--known-hosts` 指定其它路径。

## 备份与恢复

```bash
# 停服务后备份
systemctl stop ctfbb
tar -czf ctfbb-backup-$(date +%F).tar.gz -C /var/lib ctfbb
systemctl start ctfbb
```

恢复时把整个目录放回原位置即可。`state.json` 是明文，备份文件请按敏感数据保管。

## 改密码

状态库不使用密码加密，密码只用于登录。停止服务端，用新密码启动即可：

```bash
CTFBB_PASSWORD='new-password' ./ctfbb-server --data /var/lib/ctfbb ...
```

`state.json` 不需要迁移。

## 常见问题

**容器位满了，但占用者不在线？**
在容器位页面释放对应条目。释放会记录到动态，历史可查。

**客户端提示指纹变化？**
确认服务器是否换过证书。如果是正常换证，先删除 known_hosts 中对应条目，再用 `server-info.txt` 或“高级”填入新指纹。不要在不确认的情况下接受新指纹。

**服务端重启后设置变了？**
检查是否误用了另一份 `--data` 目录。设置和数据都在 `state.json` 里。

**浏览器没声音？**
浏览器要求一次用户交互才允许音频；正常点击“进入黑板”即可。检查右上角 🔔 是否被静音。
