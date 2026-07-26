# CryptoWrapper RPC v1

[English](RPC.md)

CryptoWrapper 通过 JSON-RPC 2.0 提供本地应用接口。SwiftUI、Wails、Go、Rust、
Python 等应用可以复用 `cw` CLI 的算法策略、参数校验、原子写入和 OpenSSL 调用
路径，不需要重新拼接命令。

RPC v1 仅用于本机，不监听 TCP 端口，也不安装常驻 daemon。应用负责启动和结束
子进程：

```text
cw rpc --stdio [--secret-fd 3]
```

机器可读的规范位于 [`api/openrpc.json`](api/openrpc.json)，运行中的服务也会通过
`rpc.discover` 返回同一份 OpenRPC 文档。

## 传输约定

- stdin 每行接收一个紧凑 JSON-RPC 2.0 对象，以 LF 结尾。
- stdout 只能包含协议消息。
- stderr 只输出已脱敏诊断，可以展示给用户。
- 收到全部响应前不要关闭 stdin；关闭 stdin 会要求子进程退出。
- 请求 ID 应为字符串或整数，响应和进度通知会返回相同 JSON 值。
- 未定义的参数字段以 JSON-RPC `-32602` 拒绝。

每次连接首先调用：

```json
{"jsonrpc":"2.0","id":"hello","method":"system.handshake"}
```

结果包含 `protocol_version`、结果 `schema_version`、构建信息、方法列表、秘密通道
状态和 CGO/libcrypto 状态。需要完整 OpenSSL/provider 诊断时调用
`system.doctor`。

标准接口发现：

```json
{"jsonrpc":"2.0","id":"schema","method":"rpc.discover"}
```

## 方法

| 方法 | 功能 |
| --- | --- |
| `rpc.discover` | 返回内嵌 OpenRPC 文档 |
| `system.handshake` / `system.capabilities` | 协商版本并查询能力 |
| `system.doctor` | 检查 OpenSSL、provider 和 libcrypto |
| `algorithms.list` | 列出 provider 算法 |
| `key.generate` / `key.generateSymmetric` | 生成非对称或对称密钥 |
| `key.derive` | 派生 ECDH/XDH 共享秘密 |
| `certificate.generate` / `certificate.issue` | 生成或签发证书 |
| `file.encrypt` / `file.decrypt` | 证书收件人 CMS |
| `file.encryptSymmetric` / `file.decryptSymmetric` | 原始密钥 CMS |
| `file.encryptPassword` / `file.decryptPassword` | 密码 CMS |
| `file.sign` / `file.verify` | 独立签名与验签 |
| `file.hash` / `file.inspect` | 哈希与文件检查 |
| `compat.encrypt` / `compat.decrypt` | 显式使用未认证 `enc` 兼容格式 |
| `operation.cancel` | 取消正在执行的请求 |

操作结果继续使用 CLI 的 JSON 契约：

```json
{
  "schema_version": "1",
  "ok": true,
  "algorithm": "ed25519",
  "outputs": {
    "private_key": "/absolute/alice.key.pem",
    "public_key": "/absolute/alice.pub.pem"
  },
  "fingerprints": {
    "public_key": "SHA256:..."
  }
}
```

大文件只传路径，不将文件 Base64 放入 JSON。RPC 与 CLI 使用相同的覆盖保护、
符号链接拒绝、原子写入和文件权限。

## 秘密通道

口令不能进入 JSON、argv、环境变量、进度通知或日志。启动子进程时继承一个只读
文件描述符：

```text
cw rpc --stdio --secret-fd 3
```

应用向管道另一端写入一次性 `CWS1` 帧。所有整数均为无符号大端序：

| 偏移 | 大小 | 含义 |
| --- | ---: | --- |
| 0 | 4 | ASCII 魔数 `CWS1` |
| 4 | 2 | UTF-8 `secret_ref` 字节长度，1–256 |
| 6 | 4 | 秘密长度，0–65,536 字节 |
| 10 | 可变 | UTF-8 `secret_ref` |
| 后续 | 可变 | 秘密字节 |

JSON 中只放对应的不透明引用：

```json
{
  "jsonrpc": "2.0",
  "id": "generate-alice",
  "method": "key.generate",
  "params": {
    "algorithm": "ed25519",
    "out": "/absolute/alice.key.pem",
    "secret_ref": "secret-7bff7b68"
  }
}
```

秘密帧可以在请求之前或之后写入，并按引用分发；每个引用只能领取一次。服务最多
缓存 32 个尚未领取的帧，多个秘密操作可以并发。操作结束后秘密缓冲区会清零。
重复引用、畸形帧、缺少秘密通道或超过 64 KiB 均返回 RPC 错误码 `1010`。

若明确使用未加密私钥，应省略 `secret_ref` 并设置：

```json
{"no_passphrase":true}
```

两个字段同时出现会被拒绝。

完整 Go 调用示例：

```sh
go run ./examples/go-rpc-client ./bin/cw /absolute/output.key.pem
```

Swift 请求、响应和进度处理示例位于
[`examples/swift/CryptoWrapperRPC.swift`](examples/swift/CryptoWrapperRPC.swift)。
正式 Swift 客户端可以用 `posix_spawn_file_actions_adddup2` 将秘密管道挂载到子进程
的文件描述符 3。

## 进度与取消

操作会发送 `operation.progress` 通知，阶段包括：

```text
started
awaiting_secret
running
completed
failed
cancelled
```

通知不需要响应。取消请求时必须使用原请求完全相同的 JSON ID：

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-1",
  "method": "operation.cancel",
  "params": {
    "request_id": "generate-alice"
  }
}
```

取消会通过 Go context 传到 OpenSSL 子进程；原子写入不会留下不完整目标文件。

## 错误码

标准 JSON-RPC 错误继续使用负数错误码。应用错误为：

| 错误码 | 含义 | CLI 退出码 |
| ---: | --- | ---: |
| `1001` | 一般操作失败 | `1` |
| `1002` | 操作参数错误 | `2` |
| `1003` | 缺少或不支持依赖 | `3` |
| `1004` | 验签或认证失败 | `4` |
| `1010` | 秘密通道失败 | 不适用 |

应用错误的 `data` 包含 `schema_version`，适用时包含 `cli_exit_code`。错误消息和
数据不得包含秘密。

## 兼容性

- RPC v1 可以增加新方法和可选结果字段。
- v1 内不会不兼容地改变现有方法或字段含义。
- 破坏性请求或传输变更必须提升协议版本。
- 客户端执行密码操作前必须调用 `system.handshake` 并拒绝不支持的协议版本。
- 客户端应忽略未知结果字段，以兼容增量扩展。

本接口尚未经过独立密码学安全审计。
