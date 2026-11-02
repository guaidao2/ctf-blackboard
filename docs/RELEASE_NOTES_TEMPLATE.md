# CTF Blackboard vX.Y.Z

发布日期：YYYY-MM-DD

## 亮点

- 
- 
- 

## 升级说明

- 从上一版本升级时需要注意的变化。
- 如果有 breaking change，写清楚迁移步骤。

## 下载

| 平台 | 文件 |
| --- | --- |
| Linux amd64 | `ctfbb-X.Y.Z-linux-amd64.tar.gz` |
| Linux arm64 | `ctfbb-X.Y.Z-linux-arm64.tar.gz` |
| Windows amd64 | `ctfbb-X.Y.Z-windows-amd64.zip` |
| macOS amd64 | `ctfbb-X.Y.Z-darwin-amd64.tar.gz` |
| macOS arm64 | `ctfbb-X.Y.Z-darwin-arm64.tar.gz` |

所有压缩包都包含 `ctfbb-server`、`ctfbb-client`、`README.md` 和 `LICENSE`。

## 快速开始

```bash
export CTFBB_PASSWORD='...'
./ctfbb-server --listen 0.0.0.0:8443 --data ./data
./ctfbb-client --nick alice
```

首次连接按提示确认服务器指纹，之后自动校验。

## 校验

```bash
sha256sum -c --ignore-missing checksums.txt
```

## License

MIT © 2026 guaidao2 & coolmoon
