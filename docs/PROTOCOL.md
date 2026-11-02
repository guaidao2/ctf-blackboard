# CTF Blackboard 协议

本文只描述客户端与服务端之间的协议。GUI 与本地 Go 客户端之间走 `127.0.0.1` 上的 HTTP/SSE，不属于这个协议。

## 1. 传输

- 只有 `wss://`，TLS 1.3。
- 服务端默认使用自签 ECDSA P-256 证书；客户端不校验证书链和主机名，而是**固定 SHA-256 指纹**。
- 首次连接使用 TOFU：客户端显示指纹，用户确认后写入 `known_hosts.json`；后续连接自动校验。服务端生成的 `server-info.txt` 是可选的带外固定方式，可以跳过首次提示：

  ```
  url=wss://10.0.0.5:8443/ws
  pin=AA:BB:...
  ```

- WebSocket 端点：`/ws`。
- 握手阶段使用文本帧；认证完成后只允许二进制加密帧。

## 2. 登录握手

### 2.1 客户端 → 服务端

```json
{"t":"hello","d":{"version":1,"nick":"alice","nonce":"<base64 32B>","client":"ctfbb-client/1.0.0"}}
```

### 2.2 服务端 → 客户端

```json
{"t":"challenge","d":{"version":1,"server":"队内黑板","salt":"<base64 16B>","nonce":"<base64 32B>","iterations":210000}}
```

每次连接使用新的随机 salt 和 server nonce，不能跨连接预计算。

### 2.3 客户端证明

```text
master = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
proof  = HMAC-SHA256(master,
            "ctfbb-auth-v1" || field("client") || field("1") ||
            field(nick) || field(nonceC) || field(nonceS))
```

`field(x)` 是 4 字节大端长度 + 原始字节，避免拼接歧义。

客户端发送：

```json
{"t":"auth","d":{"proof":"<base64 32B>"}}
```

### 2.4 服务端证明与会话建立

服务端用同样的方式计算 `field("server")` 的 HMAC，并返回：

```json
{"t":"welcome","d":{"version":1,"server":"队内黑板","you":"alice","proof":"<base64 32B>"}}
```

客户端必须验证服务端 proof，否则断开。之后双方派生方向独立的会话密钥：

```text
salt  = nonceC || nonceS
c2s   = HKDF-SHA256(master, salt, "ctfbb/session-v1|alice|client-to-server", 32)
s2c   = HKDF-SHA256(master, salt, "ctfbb/session-v1|alice|server-to-client", 32)
```

密码本身从不发送。失败时服务端返回：

```json
{"t":"error","err":"密码错误"}
```

然后关闭连接。登录失败按 IP 限速。

## 3. 加密帧

认证完成后，WebSocket 二进制帧：

```text
nonce (12B) || AES-256-GCM ciphertext || tag (16B)
```

- 算法：AES-256-GCM。
- 每个方向使用独立密钥。
- AAD：

  ```text
  direction (1B: 1=c2s, 2=s2c) || sequence (8B big-endian)
  ```

- 发送方序号从 0 开始，每帧 +1；接收方要求严格递增。
- 重放、重排、丢帧、方向反射都会导致认证失败并断开。
- 单帧明文上限 1 MiB；超过断开。
- 帧内是 UTF-8 JSON 信封。

## 4. 信封

```json
{
  "t": "req | resp | event",
  "id": "请求 ID（req）",
  "re": "对应请求 ID（resp）",
  "n": "事件名（event）",
  "ok": true,
  "err": "错误信息",
  "d": {}
}
```

### 请求

```json
{"t":"req","id":"7","d":{"cmd":"chat.send","args":{"text":"hello"}}}
```

### 响应

```json
{"t":"resp","re":"7","ok":true,"d":{}}
```

失败：

```json
{"t":"resp","re":"7","ok":false,"err":"容器位已满（1/1）：ezsql（alice）。先释放一个再开。"}
```

### 事件

```json
{"t":"event","n":"solver.upsert","d":{"solver":{},"board":{}}}
```

## 5. 连接后的初始快照

服务端在注册连接后发送 `snapshot` 事件。快照包含：

- `you`：当前昵称
- `settings`：名称、公告、题目总数、容器位上限
- `solvers`：战果元数据（**writeup 内容被清空**，只保留 `has_writeup`）
- `slots`：所有容器位（active + released）
- `chat`：最近 100 条聊天
- `activity`：最近 100 条动态
- `board`：已解/总题、容器位占用、在线操作员、服务器时间

writeup 内容不放进快照，避免大块内容挤占单帧；编辑/查看时用 `solver.get` 单独取。

## 6. 命令

| 命令 | args | 说明 |
| --- | --- | --- |
| `state.get` | `{}` | 取完整快照 |
| `chat.send` | `{text}` | 发聊天 |
| `solver.add` | `{challenge,nick,writeup}` | 记录一条战果（同一题只能一条） |
| `solver.get` | `{id}` | 取完整战果（含 writeup） |
| `solver.update` | `{id,challenge,nick,writeup}` | 编辑战果 |
| `solver.delete` | `{id}` | 删除战果 |
| `slot.open` | `{challenge,url,notes}` | 占用容器位；满了拒绝 |
| `slot.update` | `{id,challenge,url,notes}` | 编辑容器位 |
| `slot.release` | `{id}` | 释放容器位 |
| `settings.update` | `{total_challenges?,slot_limit?,motd?}` | 动态改设置 |
| `kick` | `{nick}` | 踢出在线操作员 |

所有命令串行经过服务端 Hub 锁；状态变更、持久化、广播在同一临界区内完成。

## 7. 事件

| 事件 | 数据 | 说明 |
| --- | --- | --- |
| `snapshot` | Snapshot | 登录/重连后的完整视图 |
| `board` | `{board}` | 在线人员变化 |
| `message` | `{message}` | 新聊天/系统播报 |
| `solver.upsert` | `{solver,board}` | 战果新增/修改 |
| `solver.delete` | `{id,board}` | 战果删除 |
| `slot.upsert` | `{slot,board}` | 容器位新增/修改/释放 |
| `settings` | `{settings,board}` | 设置变化 |
| `activity` | `{activity}` | 动态 |
| `kicked` | `{by,reason}` | 被踢通知 |

## 8. 重连

- 客户端检测到断开后按 2/4/8/15/30 秒退避重连。
- 每次重连都是**全新的握手**：新 salt、新 nonce、新会话密钥，不做会话票据/恢复。
- 重连成功后重新 `state.get`，服务端发送新快照；客户端缓存期间的事件按时间/ID 去重，避免旧事件覆盖新状态。
- 被踢昵称有 2 分钟冷却；冷却期间重连会收到 `error`。

## 9. 错误与关闭

- 握手超过 15 秒、帧过大、序号错误、解密失败、非预期帧类型都会直接关闭连接。
- 命令错误只返回 `ok:false`，不关闭连接。
- 服务端写入状态失败时，命令返回错误；内存状态保留，下一次成功写入会落盘。
- 服务端优雅关闭时先关闭所有连接，再保存状态。

## 10. 边界

- 昵称：1–24 个字符，只允许中英文、数字、`_ - .`，不能有空格/控制字符；`system/server/系统/服务端` 保留。
- 题目名：1–80 字符。
- 聊天：1–2000 字符；每连接 3 秒最多 8 条。
- writeup：最大 256 KiB（UTF-8）。
- 容器位上限：0–1000；题目总数：0–10000。
- 聊天保留最近 2000 条，动态保留最近 1000 条（服务端状态库）。

## 11. 明确的非目标

- 不做端到端加密的“私聊”；单密码模式下没有用户级密钥。
- 不做状态库落盘加密；`state.json` 是明文。
- 不做多服务器集群/消息总线；一个服务端实例对应一块黑板。
