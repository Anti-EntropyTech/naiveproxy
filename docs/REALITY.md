# NaïveProxy 的 REALITY 客户端支持

开发记录。本文档的写法以「让一个没有任何上下文的人（或 AI）能迅速接手」为目标。

## 当前状态

| 部分 | 状态 |
| --- | --- |
| BoringSSL ClientHello 认证 | 已实现，已通过语法检查 |
| Chromium 证书校验 | 已实现，**未在本地编译验证** |
| naive 配置选项 | 已实现 |
| 对真实服务端的握手测试 | **未做** |
| REALITY 服务端 | 独立项目，不在本仓库 |

整个改动由三个 commit 承载：

1. `reality: boringssl: Support REALITY client authentication`
2. `net: Support REALITY client authentication`
3. `naive: Add REALITY client options`

## 为什么 REALITY 适合放在这里

NaïveProxy 通过 HTTP/2（或 /3）的 `CONNECT` 建立隧道。CDN 不转发 `CONNECT`，因此 naive
无法被 CDN 前置，也就无法从 ECH 获益：在单租户服务器上，ECH 的外层 SNI（`public_name`）
和 IP 都指向你，匿名集大小为 1。

REALITY 用另一种方式解决同一个问题。ClientHello 的 SNI 指向一个与你无关的真实站点，证书
由共享密钥而非 PKI 认证，未通过认证的探测则由服务端转发到那个真实站点。不需要 CDN、不
需要 DoH、不需要 HTTPS RR，也不需要自己的域名和证书。

关键在于 REALITY **只替换 TLS 的认证机制**。naive 的 HTTP/2 `CONNECT`、padding 协议、
preamble 请求全部原封不动地坐在它之上。这就是它能干净组合的原因——与之相对，像 XHTTP 那
样的传输层替换必须挤掉 HTTP 层，而 HTTP 层**就是** naive 的协议本体。

客户端指纹也得以保全：REALITY 把载荷藏在 `session_id` 里，而 TLS 1.3 兼容模式本来就会往
这个字段填 32 字节随机数，所以 32 字节的 AES-GCM 输出与 Chrome 发送的内容不可区分。

## 协议

### 客户端认证，承载于 ClientHello 的 session_id

```
auth_key = HKDF-SHA256(
    ikm  = X25519(客户端临时 X25519 私钥, 服务端公钥),
    salt = client_random[0:20],
    info = "REALITY")                                          // 32 字节

plaintext = {1, 8, 1, 0} || BE32(unix 秒) || short_id[8]        // 16 字节

session_id = AES-256-GCM(
    key       = auth_key,
    nonce     = client_random[20:32],                          // 12 字节
    aad       = 整个序列化后的 ClientHello，其中 session_id 置零,
    plaintext = plaintext)                                     // 16 + 16 字节 tag
```

结果正好 32 字节，覆写 ClientHello body 偏移 39 处的 `session_id` 字段。

前置条件：TLS 1.3、存在 X25519 key share、无真 ECH、非 QUIC/DTLS。

### 服务端认证，承载于临时证书

认证成功后，服务端自己完成握手，使用一张自签的 **Ed25519** 证书，而它的 signature 字段
根本不是签名：

```
cert.signatureValue == HMAC-SHA512(auth_key, 证书的裸 32 字节 Ed25519 公钥)
```

客户端校验这一点，并完全跳过 PKI 验证。

认证失败时，服务端把连接转发到真实目标站点。客户端随即回落到普通的 X.509 验证，而它只在
确实到达了那个站点时才会通过。这就是探测抵抗路径，也是为什么不需要自建诱饵网站。

Xray 另外支持一个可选的 ML-DSA-65 签名，覆盖
`HMAC(auth_key, pub) || Hello.Raw || ServerHello.Raw`，放在证书的第一个扩展里。
**本实现未支持。**

## 实现位置对照

### `src/third_party/boringssl/src`

- `ssl/handshake_client.cc`
  - `ssl_setup_reality_auth()` 从 X25519 key share 推导 `auth_key`，并把
    `hs->session_id` 置零。在 `do_start_connect()` 中于 `ssl_setup_key_shares()` 与
    `ssl_setup_extension_permutation()` 之间调用。
  - `ssl_apply_reality_session_id()` 把载荷封装进已完成的 ClientHello。在
    `ssl_add_client_hello()` 末尾、**`finish_message()` 之后**调用，因为 AAD 是完整的
    序列化 ClientHello。**不要把它往前移。**
- `ssl/internal.h` —— `SSL_HANDSHAKE::reality_auth_key` / `reality_auth_key_valid`，
  以及 `SSL_CONFIG::reality_enabled` / `reality_public_key` / `reality_short_id`。
- `ssl/ssl_lib.cc`、`include/openssl/ssl.h`、`include/openssl/prefix_symbols.h` ——
  `SSL_set_reality_client_auth()` 与 `SSL_get0_reality_auth_key()`。

### `src/net`

- `net/ssl/ssl_config_service.h` —— `struct RealityConfig { public_key[32];
  short_id[8]; }` 以及 `SSLContextConfig::reality_configs`，类型为
  `std::map<HostPortPair, RealityConfig>`。

  把它放在 `SSLContextConfig` 而不是每 socket 的 `SSLConfig` 上是刻意选择：
  `SSLClientContext::config()` 返回引用，且在 `SSLClientSocketImpl` 中本来就可达，因此
  不必把任何东西穿过 `connect_job_params_factory.cc` / `CommonConnectJobParams`。这让
  补丁只涉及 3 个 Chromium 文件——考虑到本仓库每个 Chrome 版本都要 rebase 到全新的
  Chromium 导入，这个差别很重要。

- `net/socket/ssl_client_socket_impl.cc`
  - `Init()` 用 `host_and_port_` 在 `context_->config().reality_configs` 里查找，命中后
    **按值**存入 `reality_config_`（context 的 config 随时可能被替换），并调用
    `SSL_set_reality_client_auth()`。REALITY 启用时跳过
    `ssl_config_.ech_config_list`。
  - `VerifyRealityCert()` 取代 PKI 验证：读取 auth key，解析叶证书的 Ed25519 SPKI 与
    `signatureValue` BIT STRING，与 `HMAC-SHA512` 比对。成功时仍然填充 `server_cert_`
    和 `server_cert_verify_result_.verified_cert`，以保证 `GetSSLInfo()` 继续可用，但不
    记录任何源自 PKI 的状态。
  - `VerifyCert()` 在进入常规路径之前分发到它。

### `src/net/tools/naive`

- `naive_config.{h,cc}` —— 解析 `reality-public-key`（无填充 base64url，43 个字符，
  32 字节）和 `reality-short-id`（最多 16 个十六进制字符，8 字节，右侧补零）。应用于每条
  代理链的**最后一个**服务器，也就是协商 padding 的那一个。若最后一跳不是 `https` 则拒绝。
- `naive_proxy_bin.cc` —— `NaiveSSLConfigService` 合并了 `no_post_quantum` 和
  `reality_configs`；builder 上只能装一个 `SSLConfigService`，所以原有的 `NoPostQuantum`
  类被并入其中。
- 命令行开关通过 `GetSwitchesAsValue()` 泛化映射到配置键，因此
  `naive_command_line.cc` 无需改动。

## 用法

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://user:pass@www.example.com",
  "reality-public-key": "<43 字符的 base64url X25519 公钥>",
  "reality-short-id": "0123abcd",
  "host-resolver-rules": "MAP www.example.com 1.2.3.4"
}
```

proxy 里的主机名**仅仅是 TLS SNI**。它应当指向一个被服务端借用的、与你无关的真实站点，
所以服务器的真实地址必须通过 `host-resolver-rules` 单独给出。

## REALITY 与 Chrome TLS 栈的一处协议冲突

REALITY 服务端**硬编码用 Ed25519 签 CertificateVerify**
（`handshake_server_tls13.go` 里 `hs.sigAlg = Ed25519`），不管客户端在
`signature_algorithms` 里通告了什么。它之所以在 Xray 上能用，是因为 **Go 的 TLS 客户端只
检查「这个算法我能不能验证」**；而 **BoringSSL 检查「这个算法我通告过没有」**，后者才符合
RFC 8446 §4.4.3。

Chromium 从不通告 Ed25519（`ssl_client_socket_impl.cc` 里的 `kVerifyPrefs` 和
`kVerifyPrefsWithMlDsa` 都没有它），uTLS 的 Chrome 指纹同样没有。所以未打补丁时握手会死在
`extensions.cc` 的 `tls12_check_peer_sigalg`，报 `SSL_R_WRONG_SIGNATURE_TYPE`（245）并发出
fatal `illegal_parameter`（alert 47），客户端侧表现为 `ERR_SSL_PROTOCOL_ERROR`（-107）。

补丁的做法是**在 REALITY 启用时容忍这个算法，而不是去通告它**——通告会改变 ClientHello 的
`signature_algorithms`，从而改变 JA3/JA4 指纹，那正是本项目要避免的。放宽这个检查不损失
安全性：证书是靠它携带的 MAC 认证的，不是靠这个签名。

顺带一个设计观察：REALITY 用 Ed25519 不是随意选的，而是**承重的**——Ed25519 签名恒为 64
字节，所以可以就地整段覆写成 HMAC-SHA512 而不破坏 DER 长度编码。换成 ECDSA（签名是变长
DER）就做不到这一点。

## 不显而易见的约束

- **SNI 不是地址。** 见上。忘了写 `host-resolver-rules` 会让你真的连到被借用的站点，
  得到一个 PKI 校验通过、但 REALITY 校验失败的握手。
- **REALITY 与真 ECH 互斥。** 如果 `hs->selected_ech_config` 被设置，
  `ssl_setup_reality_auth()` 会报错，因为内外层 ClientHello 的拆分会丢弃 `session_id`。
  GREASE ECH 走的是另一条代码路径，保持启用（`SSLContextConfig::ech_enabled` 默认为
  true），而且**必须**保持启用以维持与 Chrome 的指纹一致。
- **不要为了 REALITY 关闭后量子。** Chromium 的 `kDefaultSSLSupportedGroups` 会为
  `X25519MLKEM768` 和 `X25519` 都发送 key share，所以 REALITY 需要的那个 X25519 share
  本来就在。Xray 的服务端也能处理 `X25519MLKEM768` 的 ServerHello share。用
  `--no-post-quantum` 只会毫无收益地偏离 Chrome。
- **不支持 QUIC/HTTP-3。** REALITY 认证的是 TLS 1.3 握手；BoringSSL 补丁会拒绝 QUIC 和
  DTLS，naive 的配置解析也会拒绝非 `https` 的最后一跳。
- **AAD 是整个 ClientHello。** 任何在载荷封装之后再往 hello 追加内容的行为都会破坏认证。
- **偏移 39** 是标准 ClientHello body 中 `session_id` 的位置。补丁在覆写前会校验前一个
  长度字节、并确认该字段仍为全零，因此布局变化会显式失败而不是静默出错。

## 下次 Chromium 导入时的 rebase 提示

上游补丁是针对 BoringSSL `922c15f` 编写的，而本仓库 `src/DEPS` pin 的是 `3a9254f`。
需要做两处适配；一旦 Chromium 把 BoringSSL 升到 opaque/impl 拆分之后，可能需要**反向**
改回去：

- `SSLImpl *const ssl = hs->ssl;` → `SSL *const ssl = hs->ssl;`
  （`handshake_client.cc`，两处）
- `FromOpaque(ssl)` → 直接使用 `ssl`（`ssl_lib.cc`，两个函数）

如果将来的导入重新引入了 `SSLImpl` / `ImplType`，请从参考补丁恢复上游写法。

## 服务端临时证书的实测形态

REALITY 服务端在认证成功后发的那张证书（`signedCert`，在 `init()` 里生成，**每进程一次**，
不是每连接、也不是编译期常量）实测为：

| | |
| --- | --- |
| 大小 | **178 字节**（启用 ML-DSA-65 时 3509 字节） |
| 主体 / 颁发者 | 都是空字符串 |
| 序列号 | 0 |
| 有效期起始 | 0001-01-01 |
| 公钥算法 | Ed25519 |
| 签名字段 | 64 字节，被覆写为 `HMAC-SHA512(AuthKey, 公钥)` |

它是一张**几乎完全空白的自签证书**，任何 PKI 校验都会立刻拒绝。这不成问题，因为
TLS 1.3 下 Certificate 消息是加密的，被动观察者看不到；主动探测者没有密钥，会被转发到真站点，
也到不了这条路径。它只会被已通过认证的客户端看到，所以不需要装得像真的。

由此得出一个实现要求：**客户端不能因为解析不出这张证书而否决连接**。本实现在 MAC 校验通过后
仍会尝试构造 `X509Certificate`（只为让 `GetSSLInfo()` 有内容可报），但失败时不影响连接。

## 已执行的验证

- 打过补丁的 BoringSSL 中，每个 `ssl/*.cc` 都能在
  `src/third_party/boringssl/src` 下通过
  `clang++ -fsyntax-only -std=c++20 -Iinclude -I.`。上面那两处 API 漂移就是这样发现的。
- CI 的 `linux (x64)` / `linux (x86)` 在 `225d1028` 上通过，且跑过 `tests/basic.sh`
  （naive 自身的端到端代理回归测试），说明改动没有破坏原有功能。
- **已用真实二进制对真实 REALITY 服务端做过握手**（`1a784d30` 的构建产物 vs
  `naive-reality-server`）。结果：**REALITY 认证成功**——服务端日志
  `hs.c.conn == conn: true`，证明 session_id 认证载荷的推导与封装是正确的，
  ClientHello 侧的补丁工作正常。握手随后死在 CertificateVerify 的签名算法上，
  即上面那一节描述的冲突，修复补丁尚未经构建验证。

## 后续步骤

1. 等含 Ed25519 签名算法补丁的构建产出，重跑联调。复现步骤：服务端用
   `naive-reality-server` 配一个可用的 `dest`（如 `dl.google.com:443`），客户端配置
   见上面「用法」一节，加上 `"host-resolver-rules": "MAP <SNI> 127.0.0.1"` 指向本机，
   然后经客户端的 SOCKS 端口发一次请求。
2. 失败时用 `"log-net-log": "<path>"` 抓 NetLog，里面会给出 BoringSSL 的
   `file`/`line`/`error_reason`，比 stderr 上那句 `handshake failed` 有用得多。诊断
   上面那处签名算法冲突就是靠它定位的。
3. REALITY 服务端已经实现完成，是一个独立的 Go 项目，不再需要 naive 作为后端。

## 参考实现

- `/root/Solaris-Core` —— 基于打过补丁的 BoringSSL 的 C 客户端。
  `third_party/boringssl-reality.patch` 是本补丁的来源；
  `src/tls_uv.c` 的 `reality_verify_certificate()` 是证书校验；
  `src/reality.c` 仅做密钥与 short id 的解析。
- `/root/Xray-core` —— Go 参考实现。
  `transport/internet/reality/reality.go` 中 `UConn::VerifyPeerCertificate()` 是客户端
  校验，包含 PKI 回落路径和可选的 ML-DSA-65 路径。
