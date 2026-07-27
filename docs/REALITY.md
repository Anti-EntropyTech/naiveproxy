# REALITY client support in NaïveProxy

Development record. This document is written so that someone (or some agent)
with no prior context can pick the work up.

## Status

| Part | State |
| --- | --- |
| BoringSSL ClientHello authentication | Implemented, syntax-checked |
| Chromium certificate verification | Implemented, **not compiled locally** |
| naive configuration options | Implemented |
| Handshake tested against a real server | **Not done** |
| REALITY server | Separate project, not in this repo |

Three commits carry the whole change:

1. `reality: boringssl: Support REALITY client authentication`
2. `net: Support REALITY client authentication`
3. `naive: Add REALITY client options`

## Why REALITY belongs here

NaïveProxy tunnels through HTTP/2 (or /3) `CONNECT`. CDNs do not forward
`CONNECT`, so naive cannot be fronted by a CDN, and therefore cannot benefit
from ECH: on a single-tenant server the ECH outer SNI (`public_name`) and the IP
both identify you, so the anonymity set is one.

REALITY solves the same problem differently. The ClientHello SNI names an
unrelated real site, the certificate is authenticated by a shared secret rather
than by the PKI, and unauthenticated probes are relayed to the real site by the
server. No CDN, no DoH, no HTTPS RR, no domain or certificate of your own.

Critically, REALITY only replaces the TLS authentication mechanism. naive's
HTTP/2 `CONNECT`, its padding protocol, and its preamble requests all sit on top
unchanged. That is why this composes cleanly, unlike a transport replacement
such as XHTTP, which would have to displace the HTTP layer that *is* naive's
protocol.

The client fingerprint also survives: REALITY hides its payload in the
`session_id`, which TLS 1.3 compatibility mode fills with 32 random bytes
anyway, so 32 bytes of AES-GCM output is indistinguishable from what Chrome
sends.

## Protocol

### Client authentication, carried in the ClientHello session_id

```
auth_key = HKDF-SHA256(
    ikm  = X25519(client ephemeral X25519 private key, server public key),
    salt = client_random[0:20],
    info = "REALITY")                                          // 32 bytes

plaintext = {1, 8, 1, 0} || BE32(unix_seconds) || short_id[8]  // 16 bytes

session_id = AES-256-GCM(
    key       = auth_key,
    nonce     = client_random[20:32],                          // 12 bytes
    aad       = the entire serialized ClientHello, session_id zeroed,
    plaintext = plaintext)                                     // 16 + 16 tag
```

The result is exactly 32 bytes and overwrites the `session_id` field at offset
39 of the ClientHello body.

Preconditions: TLS 1.3, an X25519 key share present, no real ECH, not
QUIC/DTLS.

### Server authentication, carried in the temporary certificate

On successful authentication the server completes the handshake itself with a
self-signed **Ed25519** certificate whose signature field is not a signature at
all:

```
cert.signatureValue == HMAC-SHA512(auth_key, cert's raw 32-byte Ed25519 public key)
```

The client checks that and skips PKI verification entirely.

On failed authentication the server relays the connection to the real
destination site. The client then falls back to ordinary X.509 verification,
which succeeds only if it genuinely reached that site. This is the
probe-resistance path, and it is why no self-hosted decoy website is needed.

Xray additionally supports an optional ML-DSA-65 signature over
`HMAC(auth_key, pub) || Hello.Raw || ServerHello.Raw` in the certificate's first
extension. **Not implemented here.**

## Implementation map

### `src/third_party/boringssl/src`

- `ssl/handshake_client.cc`
  - `ssl_setup_reality_auth()` derives `auth_key` from the X25519 key share and
    zeroes `hs->session_id`. Called from `do_start_connect()` between
    `ssl_setup_key_shares()` and `ssl_setup_extension_permutation()`.
  - `ssl_apply_reality_session_id()` seals the payload into the finished
    ClientHello. Called at the end of `ssl_add_client_hello()`, **after**
    `finish_message()`, because the AAD is the complete serialized ClientHello.
    Do not move it earlier.
- `ssl/internal.h` — `SSL_HANDSHAKE::reality_auth_key` / `reality_auth_key_valid`,
  and `SSL_CONFIG::reality_enabled` / `reality_public_key` / `reality_short_id`.
- `ssl/ssl_lib.cc`, `include/openssl/ssl.h`, `include/openssl/prefix_symbols.h` —
  `SSL_set_reality_client_auth()` and `SSL_get0_reality_auth_key()`.

### `src/net`

- `net/ssl/ssl_config_service.h` — `struct RealityConfig { public_key[32];
  short_id[8]; }` and `SSLContextConfig::reality_configs`, a
  `std::map<HostPortPair, RealityConfig>`.

  This lives on `SSLContextConfig` rather than per-socket `SSLConfig`
  deliberately: `SSLClientContext::config()` returns a reference and is already
  reachable from `SSLClientSocketImpl`, so nothing has to be threaded through
  `connect_job_params_factory.cc` / `CommonConnectJobParams`. That keeps the
  patch to three Chromium files, which matters because this tree is rebased onto
  a fresh Chromium import for every Chrome release.

- `net/socket/ssl_client_socket_impl.cc`
  - `Init()` looks up `host_and_port_` in `context_->config().reality_configs`,
    stores the hit **by value** in `reality_config_` (the context's config may be
    replaced at any time), and calls `SSL_set_reality_client_auth()`.
    `ssl_config_.ech_config_list` is skipped while REALITY is active.
  - `VerifyRealityCert()` replaces PKI verification: reads the auth key, parses
    the leaf certificate's Ed25519 SPKI and `signatureValue` BIT STRING, and
    compares against `HMAC-SHA512`. On success it still populates
    `server_cert_` and `server_cert_verify_result_.verified_cert` so
    `GetSSLInfo()` keeps working, but records no PKI-derived status.
  - `VerifyCert()` dispatches to it before the normal path.

### `src/net/tools/naive`

- `naive_config.{h,cc}` — parses `reality-public-key` (unpadded base64url, 43
  characters, 32 bytes) and `reality-short-id` (at most 16 hex digits, 8 bytes
  right-zero-padded). Applied to the **last** server of every proxy chain, which
  is the same server that negotiates padding. Rejects a last hop that is not
  `https`.
- `naive_proxy_bin.cc` — `NaiveSSLConfigService` merges `no_post_quantum` and
  `reality_configs`; only one `SSLConfigService` can be installed on the builder,
  so the pre-existing `NoPostQuantum` class was folded into it.
- Command line switches map to config keys generically via
  `GetSwitchesAsValue()`, so no changes were needed in `naive_command_line.cc`.

## Usage

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://user:pass@www.example.com",
  "reality-public-key": "<43-char base64url X25519 public key>",
  "reality-short-id": "0123abcd",
  "host-resolver-rules": "MAP www.example.com 1.2.3.4"
}
```

The proxy hostname is only the TLS SNI. It should name an unrelated real site
that the server borrows, which is why the real server address has to be supplied
separately through `host-resolver-rules`.

## Non-obvious constraints

- **SNI is not the address.** See above. Forgetting `host-resolver-rules` means
  you connect to the borrowed site itself and get a PKI-valid handshake that
  fails REALITY verification.
- **REALITY excludes real ECH.** `ssl_setup_reality_auth()` errors out if
  `hs->selected_ech_config` is set, because the inner/outer ClientHello split
  would discard the `session_id`. GREASE ECH is a different code path, is left
  enabled (`SSLContextConfig::ech_enabled` defaults to true), and must stay
  enabled for Chrome fingerprint parity.
- **Do not disable post-quantum for REALITY.** Chromium's
  `kDefaultSSLSupportedGroups` sends key shares for both `X25519MLKEM768` and
  `X25519`, so the X25519 share REALITY needs is already there. Xray's server
  handles an `X25519MLKEM768` ServerHello share. Using `--no-post-quantum` would
  deviate from Chrome for no benefit.
- **No QUIC/HTTP-3.** REALITY authenticates a TLS 1.3 handshake; the BoringSSL
  patch rejects QUIC and DTLS, and the naive config rejects a non-`https` last
  hop.
- **The AAD is the whole ClientHello.** Anything that appends to the hello after
  the payload is sealed breaks authentication.
- **Offset 39** is the `session_id` position in a standard ClientHello body. The
  patch validates the preceding length byte and that the field is still zeroed
  before overwriting, so a layout change fails loudly rather than silently.

## Rebase notes for the next Chromium import

The upstream patch was authored against BoringSSL `922c15f`; this tree's
`src/DEPS` pins `3a9254f`. Two adaptations were needed, and the *reverse* may be
needed once Chromium bumps BoringSSL past the opaque/impl split:

- `SSLImpl *const ssl = hs->ssl;` → `SSL *const ssl = hs->ssl;`
  (`handshake_client.cc`, two occurrences)
- `FromOpaque(ssl)` → use `ssl` directly (`ssl_lib.cc`, two functions)

If a future import reintroduces `SSLImpl` / `ImplType`, restore the upstream
spelling from the reference patch.

## Verification performed

- Every `ssl/*.cc` in the patched BoringSSL passes
  `clang++ -fsyntax-only -std=c++20 -Iinclude -I.` from
  `src/third_party/boringssl/src`. This is what caught both API drifts above.
- The Chromium-side files were **not** compiled locally; the toolchain is
  fetched by `src/get-clang.sh` and the build runs in GitHub Actions on pushes
  to `master`.
- No handshake has been attempted against a real REALITY server yet.

## Next steps

1. Get the CI build green.
2. Point the client at an **Xray** REALITY server as a test harness. The
   handshake and REALITY authentication should succeed; the inner protocol will
   not, because Xray expects VLESS where naive sends HTTP/2 `CONNECT`. A
   successful handshake is sufficient to validate this patch series.
3. Build the REALITY server. The intended shape is a REALITY + HTTP/2 frontend
   that forwards `CONNECT` to a plain naive server backend
   (`naive --listen=http://127.0.0.1:8080`), reusing naive's padding
   implementation rather than reimplementing it. Note that naive's own server
   side is plaintext HTTP/1.1 (`http_proxy_server_socket.cc`, `kResponseHeader`)
   and expects to sit behind a TLS/H2 frontend.

## Reference implementations

- `/root/Solaris-Core` — C client on patched BoringSSL.
  `third_party/boringssl-reality.patch` is the source of this patch;
  `src/tls_uv.c` `reality_verify_certificate()` is the certificate check;
  `src/reality.c` is only key/short-id parsing.
- `/root/Xray-core` — Go reference.
  `transport/internet/reality/reality.go` `UConn::VerifyPeerCertificate()` is the
  client check, including the PKI fallback and the optional ML-DSA-65 path.
