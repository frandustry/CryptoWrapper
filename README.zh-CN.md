# CryptoWrapper

[English](README.md)

CryptoWrapper（`cw`）是一个更安全、更易用的 OpenSSL Go CLI 包装器。它用较短的
命令完成现代经典密码、国密和后量子算法的密钥生成、签名、密钥协商及标准 CMS
文件加密。

> [!WARNING]
> 本项目尚未经过独立密码学安全审计，不能替代经过评审的生产密钥管理系统。

## 环境要求

- Go 1.25 或更新版本。
- OpenSSL 3.6.3+ 或 4.0.1+。
- 默认 CGO 构建需要 OpenSSL 头文件、库和 `pkg-config`。
- macOS 或 Linux。

程序会拒绝 OpenSSL 3.6.0–3.6.2，因为 3.6.3 包含与 CMS 处理有关的安全修复。
`openssl` 命令与 CGO 链接的 `libcrypto` 必须属于相同 major/minor 系列。每个依赖
OpenSSL 命令行的操作都会在执行前检查版本；直接使用 CGO CMS 的命令也会检查
链接库版本。运行 `cw doctor` 可查看完整的路径、provider 和链接诊断。
`cw version`、`cw completion` 以及纯 Go 的 `cw symkey` 不需要 OpenSSL 可执行文件。

macOS Homebrew：

```sh
brew install go openssl@3 pkg-config
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
```

Linux 需要 OpenSSL 3.6.3+ 开发文件。如果发行版版本较旧，请自行安装受支持的
OpenSSL，并正确设置 `PATH`、`PKG_CONFIG_PATH` 和动态库路径。

## 构建与安装

```sh
git clone https://github.com/frandustry/CryptoWrapper.git
cd CryptoWrapper
make check
make build
./bin/cw doctor
```

安装到 Go 二进制目录：

```sh
make install
```

生成 Bash、Zsh 和 Fish 补全：

```sh
make completions
```

其他应用可以通过带版本的本地 JSON-RPC 接口调用 CryptoWrapper，无需重新拼接
CLI 参数。参见 [CryptoWrapper RPC v1](RPC.zh-CN.md)、内嵌
[OpenRPC 规范](api/openrpc.json) 以及 `examples/` 下的 Go 和 Swift 示例。

也可以使用 `CGO_ENABLED=0 go build ./cmd/cw`。无 CGO 版本仍支持密钥、证书、
签名、证书收件人 CMS、哈希和兼容命令，但会明确拒绝密码 CMS 和原始对称密钥
CMS。

## 预编译版本

推送 `v0.1.0` 之类的语义化版本标签后，GitHub Actions 会自动为 Linux 和
macOS 的 AMD64、ARM64 架构编译并发布 Release。每个 Release 都包含单独的
SHA-256 校验文件和汇总的 `SHA256SUMS`。

预编译程序仍需要上文所述的兼容 OpenSSL 环境。安装包长期保存在 GitHub
Releases 中，Actions 中转 artifact 只保留一天。

当前 macOS 压缩包没有 Developer ID 签名，也没有经过 Apple 公证。ARM64 文件
可能带有 Go 链接器生成的 ad-hoc 签名，而 AMD64 文件可能完全未签名；两者都不能
建立可信开发者身份。推荐 macOS 用户按上文 Homebrew 配置从源码编译。高级用户若
使用预编译包，应先验证 SHA-256 校验和，也可以在本机应用或替换 ad-hoc 签名：

```sh
codesign --force --sign - ./cw
codesign --verify --verbose=2 ./cw
```

ad-hoc 签名不代表 Developer ID 身份，也不等同于 Apple 公证；Gatekeeper 仍可能
要求用户在“系统设置”中明确批准这个程序。

## 快速使用

生成默认 3072 位、加密保存的 RSA 密钥：

```sh
cw keygen rsa \
  --out alice.key.pem \
  --public-out alice.pub.pem
```

脚本中应使用权限为 `0600` 的口令文件：

```sh
cw keygen ed25519 \
  --passphrase-file private-passphrase.txt \
  --out signing.key.pem \
  --public-out signing.pub.pem
```

生成自签名证书：

```sh
cw certgen \
  --key alice.key.pem \
  --subject /CN=Alice \
  --days 365 \
  --out alice.crt.pem
```

为一个或多个证书收件人加密：

```sh
cw encrypt \
  --in document.pdf \
  --recipient alice.crt.pem \
  --recipient bob.crt.pem \
  --out document.pdf.cms

cw decrypt \
  --in document.pdf.cms \
  --cert alice.crt.pem \
  --key alice.key.pem \
  --out document.pdf
```

对称密钥认证加密：

```sh
cw symkey aes-256 --out vault.key
cw sym-encrypt --key vault.key --in archive.tar --out archive.tar.cms
cw sym-decrypt --key vault.key --in archive.tar.cms --out archive.tar
```

密码 CMS：

```sh
cw pass-encrypt \
  --passphrase-file vault-passphrase.txt \
  --in notes.txt \
  --out notes.txt.cms

cw pass-decrypt \
  --passphrase-file vault-passphrase.txt \
  --in notes.txt.cms \
  --out notes.txt
```

签名和验签：

```sh
cw sign --key signing.key.pem --in release.tar.gz --out release.tar.gz.sig
cw verify --key signing.pub.pem --in release.tar.gz --signature release.tar.gz.sig
```

哈希和密钥派生：

```sh
cw hash sha3-256 --in release.tar.gz
cw derive --key alice-x25519.key.pem --peer-key bob-x25519.pub.pem --out shared.secret
```

## 后量子 CMS 收件人

ML-KEM 不能自行签发证书，需要一个可签名的 CA 密钥。以下命令使用 ML-DSA
签发 ML-KEM 收件人证书：

```sh
cw keygen ml-dsa-65 --out pq-ca.key.pem --public-out pq-ca.pub.pem
cw certgen --key pq-ca.key.pem --subject /CN=PQ-CA --out pq-ca.crt.pem

cw keygen ml-kem-768 --out recipient.key.pem --public-out recipient.pub.pem
cw certissue \
  --ca-cert pq-ca.crt.pem \
  --ca-key pq-ca.key.pem \
  --public-key recipient.pub.pem \
  --subject /CN=PQ-Recipient \
  --out recipient.crt.pem
```

生成的证书可直接传给 `cw encrypt --recipient`。

## 算法和安全策略

`cw algorithms keys|ciphers|digests|signatures` 会显示当前 OpenSSL provider
真实提供的算法。添加 `--json` 可获得稳定的 schema-v1 机器输出。

主要支持：

- RSA、RSA-PSS、P-256/P-384/P-521/secp256k1 EC。
- Ed25519、Ed448、X25519、X448。
- SM2、SM3、SM4。
- ML-KEM-512/768/1024、ML-DSA-44/65/87。
- OpenSSL provider 提供的 SLH-DSA 变体。
- AES、ChaCha20、Camellia、ARIA 和 SM4 对称密钥。

DES、3DES、RC2、RC4、Blowfish、CAST、IDEA、DSA、MD5 和 SHA-1 必须显式
添加 `--allow-legacy`。OpenSSL `enc` 格式没有认证保护，还必须使用
`cw compat ... --allow-unauthenticated`。

## 秘密处理

- 私钥默认加密，只有显式 `--no-passphrase` 才生成未加密私钥。
- 口令来自隐藏终端、`--passphrase-file` 或 `--passphrase-env`，不提供明文
  口令参数。
- 密码和原始对称密钥 CMS 通过 `libcrypto` 直接处理，不把秘密放入进程参数。
- 私钥和对称密钥权限为 `0600`。
- 输出先写入同目录临时文件，再原子落盘；默认拒绝覆盖和符号链接。
- 认证失败时不会留下最终明文文件。

## 稳定退出码

| 代码 | 含义 |
| ---: | --- |
| 0 | 成功 |
| 1 | 一般运行或 I/O 错误 |
| 2 | 参数错误或违反安全策略 |
| 3 | 缺少依赖或算法不受支持 |
| 4 | 验签失败或解密认证失败 |

## 许可

CryptoWrapper 使用 `GPL-3.0-only`，参见 [LICENSE](LICENSE) 和
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
