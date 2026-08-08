# Alibaba Cloud vTPM Attestation - Research Notes

## Overview

Alibaba Cloud (Aliyun) ECS security-enhanced instances include a vTPM (TPM 2.0 compatible).
The trust agent (`t-trustclient`) runs on the instance and handles attestation automatically.

## Certificate Chain (EK)

Downloaded from public OSS bucket. Chain verifies cleanly.

```
Root:         C=CN, O=Aliyun, OU=Aliyun TPM Root CA, CN=Aliyun TPM Root CA
              RSA 2048, self-signed, sha384WithRSA, valid until 2030
              URL: https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt

Intermediate: C=CN, O=Aliyun, OU=Aliyun TPM Endorsement Key Manufacture CA, CN=Aliyun TPM EKMF CA
              RSA 2048, signed by root, sha384WithRSA, valid until 2030
              URL: https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt
              CRL: https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crl
```

No AK/AIK certificates found at the OSS bucket (tried various guesses, all 403).
Bucket listing is access-denied.

## Trust Agent Package

Available from public OSS buckets per region:
```
http://trustclient-${REGION_ID}.oss-${REGION_ID}.aliyuncs.com/download/linux/ubuntu/x86_64/${VERSION}/t-trustclient-${VERSION}-x86_64.deb
```

Current version: 1.1.0 (as of 2026-02-07)
Available in: cn-beijing, cn-hangzhou, cn-shanghai, us-east-1, ap-southeast-1 (NOT us-west-1)

### Package Contents
```
/etc/ali_trust_net.conf                          # config
/usr/local/bin/trust-agent                       # main binary
/usr/lib/systemd/system/t-trustclient.service    # systemd unit
/usr/lib/libtrust.so.1.0.0                       # core trust library
/usr/lib/libtrust_tpm.so.1.0.0                   # TPM operations
/usr/lib/libtrust_network.so.1.0.0               # network/API calls (statically linked against libstdc++, libcurl, libssl, etc.)
/usr/lib/libtpm2-openssl.so.1.0.0                # TPM2 OpenSSL provider
/usr/lib/libtpm2-tools.so.1.0.0                  # TPM2 tools
/usr/lib/libtss2-tcti-device.so.1.0.0            # TSS2 TCTI device
```

Built from: `trustclient-opensource/third_party/ali-trust-sdk/` (source paths in binary)
Key source files referenced: `tpm_net_api.cpp`, `tpm_pop_visitor.cpp`, `tpm_http_visitor.cpp`

## Configuration (`ali_trust_net.conf`)

Key settings:
- `REGION_ID` - auto-detected from instance metadata
- `DEFAULT_SERVICE_ENDPOINT` / `TRUSTED_SERVER_ENDPOINT` - e.g. `trusted-server-vpc.cn-hangzhou.aliyuncs.com`
- `QUOTE_SERVER_ENDPOINT` - separate endpoint for quote submission
- `AIKSS_SERVER_ENDPOINT` - separate endpoint for AIK signing service
- `POP_ENABLED=TRUE` - use Alibaba Cloud POP API gateway (vs direct HTTP)
- `HTTP_ENABLED` - for direct HTTP mode (bypasses POP)
- `INCREMENT_IMA=FALSE` - incremental IMA log submission
- `ACCESS_KEY` / `ACCESS_SECRET` - for classic credential mode

## Authentication & Visitor Architecture

Two visitor implementations (`TpmVisitor` is the base interface):

### TpmPopVisitor (default, `POP_ENABLED=TRUE`)
- Uses Alibaba Cloud POP (Platform of Platforms) API gateway
- Authenticates via `PopVisitor::validateCredential()` / `PopVisitor::refreshCredential()`
- Creates either `VpcCredential` or `ClassicCredential` depending on config
- Calls `yundun-systrust` API actions: `GenerateNonce`, `GenerateAikcert`, `ProduceAikcert`,
  `RegisterMessage`, `PutMessage`, `QuoteMessage`

### TpmHttpVisitor (fallback, `HTTP_ENABLED=TRUE`)
- Direct HTTP POST to `trusted-server-vpc.{region}.aliyuncs.com`
- **No authentication on the HTTP requests themselves** - relies on:
  1. Network-level gating (VPC-only endpoint, `-vpc` suffix)
  2. TPM cryptographic binding (MakeCredential blobs are useless without the real TPM)
- Uses `CurlUtils::http_post` with JSON request/response

### Credential types
1. **VpcCredential** (default) - uses instance metadata at `http://100.100.100.200/latest/meta-data/ram/security-credentials/` to get temporary `AccessKeyId`, `AccessKeySecret`, `SecurityToken`, `Expiration`
2. **ClassicCredential** - static access key/secret from config

### Endpoint construction (from `ali_trust_init_tpm_visitor` decompilation)
When no explicit endpoint is configured, constructs:
```
"trusted-server-vpc." + GuestInfo.region_id + ".aliyuncs.com"
```
Also reads `AIKSS_SERVER_ENDPOINT` and `QUOTE_SERVER_ENDPOINT` from `NetConfig` singleton.

## trust-agent Main Flow (from Hex-Rays decompilation)

```
main():
  1. Print "Trust Agent Version: 9a6e56c17362ced8592fb5ca3a509ad59185598d"
  2. Create logger → /var/log/trust-agent
  3. Create scheduler(5 tasks, 1800s interval, 300s initial delay)
  4. ali_trust_tpm_init_context("9a6e56c17362ced8592fb5ca3a509ad59185598d")
  5. Schedule "instance registration" → ali_trust_tpm_register
  6. Schedule "remote attestation" → attestation_loop (sub_BA00)
```

### Attestation Loop (runs every 30 minutes)
```
sub_BA00():
  1. ali_trust_tpm_generate_aik_cert(1, &aik_context)
     → Called EVERY cycle, not just once at boot
     → First param=1 may mean "include cert chain"
     → If fails: "error while requesting aik cert, errno: %d"

  2. ali_trust_tpm_generate_quote(aik_context, 0, 0, 0, 3, 1, 0, &quote)
     → Params: (context, ?, ?, ?, pcr_bank_mask=3?, algo=1, ?, &output)
     → If fails: "error while generating quote, errno: %d"

  3. ali_trust_tpm_attestation(quote, &result)
     → Submits quote to server, gets back ali_trust_attest_ra_result_t
     → If fails: "error while initiating remote attestation, errno: %d"

  4. Log: "system trust status: %d" (result[0])
```

## API Flow (from BinaryNinja decompilation of `libtrust_network.so`)

### Phase 1: Register (`/register`)

`TpmHttpVisitor::register_inst()` - registers the instance with the trusted server.

Request params (JSON POST):
- `RequestId` - generated UUID
- `PropertyUuid`
- `InstanceId`
- `InstanceType`
- `PropertyPublicIp`
- `PropertyPrivateIp`
- `PropertyName`
- `PropertyAffiliation`

Response: `httpStatusCode`

### Phase 2: AIK Certificate (`/aikcert/produce`)

`TpmHttpVisitor::aik_cert()` - Privacy CA flow.

**Confirmed function signature (BinaryNinja):**
```cpp
uint64_t aik_cert(
    /* this */,                    // TpmHttpVisitor, base URL at this+0x70/0x78
    const string& ek_pubkey,       // → "EkPubKey"
    const string& ek_cert,         // → "EkCert"
    const string& aik_name,        // → "AikName"
    const string& cert_request,    // → "CertRequest" (CSR)
    bool include_cert_chain,       // → "IncludeCertChain" (sprintf'd as "%d")
    string& out_key_cred_blob,     // ← output: "keyCredentialBlob"
    string& out_data_cred_blob     // ← output: "dataCredentialBlob"
)
```

**Confirmed flow (from decompilation):**
1. Constructs URL: `base_url + "/aikcert/produce"`
2. Builds `std::map<string,string>` with `RequestId`, `EkPubKey`, `EkCert`, `AikName`,
   `CertRequest`, `IncludeCertChain`
3. `assemble_params()` → `CurlUtils::http_post()` (plain HTTP, no auth headers)
4. Parses JSON response with `Json::Reader::parse()`
5. Checks `json["httpStatusCode"] == 200` (0xc8)
6. On success: extracts nested `json[...]["keyCredentialBlob"]` → arg7,
   `json[...]["dataCredentialBlob"]` → arg8
7. Returns 0 on success, 0x3003 on any error

**Interpretation:** Server validates EK cert against Aliyun TPM CA chain, then uses
`TPM2_MakeCredential` to create challenge blobs. Client calls `TPM2_ActivateCredential`
(in `libtrust_tpm.so`) to prove AIK is co-resident with EK. The `CertRequest` (CSR) is
sent so the server can sign it - but the actual signed cert delivery mechanism is still
unclear (may be wrapped in the credential blobs, or may require a follow-up call).

### Phase 3: Attestation/Quote (`/quote`)

`TpmHttpVisitor::attestation()` - submits TPM quote evidence.

**Confirmed function signature:**
```cpp
uint64_t attestation(
    /* this */,
    const string& file_data,             // → "FileData" (TPM quote + IMA log)
    ali_trust_attest_ra_result_t& result, // ← output struct
    string& request_id_out               // ← output: request ID
)
```

**Confirmed flow:**
1. Constructs URL: `base_url + "/quote"` (note: uses offset 0x50/0x58, different from aik_cert's 0x70/0x78 - may use `QUOTE_SERVER_ENDPOINT`)
2. Sends `RequestId` + `FileData`
3. Parses JSON, checks `httpStatusCode == 200`
4. Extracts into result struct:
   - `systemVerificationResult` → result field (int)
   - `programVerificationResult` → result field (int, default=4 if missing)
   - `kmoduleVerificationResult` → result field (int, default=4 if missing)
   - `nextClientIMAIndex` → result field (uint64)
   - `policyProcResult` → optional, if present calls `ali_trust_elem_init_from_c_str`
     to parse `procData` into an `ali_trust_elem`

## Key Functions (from symbol tables)

### trust-agent binary
- `ali_trust_tpm_init_context` - init with version string
- `ali_trust_tpm_generate_aik_cert` - triggers the AIK cert flow
- `ali_trust_tpm_register` - registers with trusted server
- `ali_trust_tpm_generate_quote` - generates TPM quote
- `ali_trust_tpm_attestation` - submits attestation

### libtrust.so (core library - abstract interface)
- `ali_trust_quote(nonce, pcr_bank, pcr_selection, policy_effect, policy_action, extra, &output)` - quote with policy params
- `ali_trust_attestation(quote, &result)` - submit attestation, get `ali_trust_attest_ra_result_t`
- `ali_trust_generate_plat_cert` / `ali_trust_renew_plat_cert` - platform certificates
- `ali_trust_generate_app_cert` / `ali_trust_renew_app_cert` - application certificates
- `ali_trust_generate_session_credential` / `ali_trust_verify_session_credential`
- `ali_trust_inspect_plat_stat` - get `ali_trust_attest_ra_status_t`
- `ali_trust_sign`, `ali_trust_encrypt`, `ali_trust_decrypt`
- `ali_trust_create_key`, `ali_trust_import_key`, `ali_trust_export_key`
- `ali_trust_define_sb`, `ali_trust_read_sb`, `ali_trust_write_sb` (sealed blob operations)

### libtrust_tpm.so (TPM implementation)
Key types (C++ classes under `AlibabaCloud::AliTrust`):
- `TpmPlatformKey` - platform-level key
- `TpmCommonKey` - general purpose key
- `TpmUserImportedKey` - user-imported key
- `TpmPreGeneratedKey` - pre-provisioned key
- `TpmCommonNonVolatile` / `TpmPreGeneratedNonVolatile` - NV storage

### libtrust_network.so (network layer)
Class hierarchy:
```
CommonVisitor (base)
├── PopVisitor
│   └── TpmPopVisitor (POP API gateway, authenticated)
└── TpmHttpVisitor (direct HTTP, VPC-only)

CommonCredential (base)
├── VpcCredential (instance metadata RAM creds)
└── ClassicCredential (static access key/secret)

NetConfig (singleton) - reads ali_trust_net.conf
GuestInfo (singleton) - instance metadata (region, IPs, etc.)
MachineInfo (singleton) - machine-level info
```

Virtual method table (both visitors implement same interface):
- `register_inst(uuid, instance_id, instance_type, public_ip, private_ip, name, &affiliation)`
- `aik_cert(ek_pubkey, ek_cert, aik_name, cert_request, include_chain, &key_blob, &data_blob)`
- `attestation(file_data, &ra_result, &request_id)`

### Trusted_serverClient operations (POP path, from C++ mangled names)
- `registerMessageCallable` → `/register` equivalent
- `verifyMessageCallable` → `/quote` equivalent
- `updateComponentCallable`
- `unregisterMessageCallable`
- `trustEventsCallable`

## TDX vs vTPM Attestation

Alibaba has TWO completely separate attestation paths:

| Aspect | vTPM | TDX |
|--------|------|-----|
| Endpoint | `trusted-server-vpc.{region}.aliyuncs.com` | `attest.{region}.aliyuncs.com` |
| Auth | VPC-only + POP gateway (or plain HTTP) | Anonymous HTTP POST |
| Response | Structured JSON (PCR values, trust status) | JWT (OIDC-compliant, RS256) |
| JWKS | N/A | `https://attest.cn-beijing.aliyuncs.com/jwks.json` |
| EAT Profile | Not documented | Documented |
| Certificate | AIK cert via Privacy CA flow | N/A (enclave attestation) |

## OIDC Discovery (TDX path only)

```json
{
  "issuer": "https://attest.cn-beijing.aliyuncs.com",
  "jwks_uri": "https://attest.cn-beijing.aliyuncs.com/jwks.json",
  "token_endpoint": "https://attest.cn-beijing.aliyuncs.com/token",
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

JWKS has one key: RSA, kid=`4653550c-5551-5e6f-92b5-22f530229751`

## Decompilation Artifacts (Summary)

See the detailed line-number index in the "Decompilation Artifacts" section below (after the TPM Internals section).

## TPM Internals (from BinaryNinja decompilation of `libtrust_tpm.so`)

### TPM Handle Defaults (`TpmPlatformKey` static constants)

| Handle | Hex Value | Purpose |
|--------|-----------|---------|
| `ekDefaultKeyHandle` | `0x81010001` | EK persistent key (standard TPM2 EK at 0x81010001) |
| `ekDefaultCertHandle` | `0x01c00002` | EK cert NV index (standard TPM2 EK cert NV) |
| `aikDefaultKeyHandle` | `0x81010003` | AIK persistent key (Alibaba-specific) |
| `aikDefaultNameNvHandle` | `0x1001000` | AIK name NV storage (Alibaba-specific) |

### TPM Device Architecture

Three-layer abstraction for TPM operations:

```
TpmDeviceProxy (dispatcher)
├── TpmToolsOpsImpl (ITpmDeviceOps)
│   └── tpm2_init() → tpm2_set_option(cmd, key, val) → tpm2_run(cmd, buf, size) → flush_tpm_context()
│   └── Uses libtpm2-tools.so (custom, NOT upstream tpm2-tools)
└── TpmSslOpsImpl (ITpmDeviceOps)
    └── Uses OpenSSL with libtpm2-openssl provider
    └── Provider searched at /usr/lib64 then /usr/lib
    └── Operations like decrypt/encrypt/sign via OpenSSL EVP API with TPM keys
```

`TpmDeviceProxy::run(cmd_id, option_map, output_elem)`:
- Takes a `tpm_ops_cmd_t` command ID (0-29, 0x1d max)
- Routes to either TpmToolsOpsImpl or TpmSslOpsImpl based on command type
- Holds a vector of `(tpm_ops_type_t, shared_ptr<ITpmDeviceOps>)` pairs
- Acquires `TpmLock` before running (mutex-protected TPM access)

### AIK Certificate Generation - FULL FLOW (RESOLVED)

**`TpmAttestationImpl::generate_aik_cert(bool include_chain, _ali_trust_elem& output)`**

This is the complete Privacy CA flow. Decompiled from line 96987 of the BN export.

```
Phase A: Prepare TPM Objects
  1. Parse aikDefaultKeyHandle ("0x81010003") from hex string → uint64
  2. Create TpmPreGeneratedKey(handle=0x81010003, algorithm=1)
     → This is a shared_ptr, represents the AIK key in TPM persistent storage
  3. Parse aikDefaultNameNvHandle ("0x1001000") → uint64
  4. Create TpmPreGeneratedNonVolatile(nv_index=0x1001000)
     → For AIK name storage

Phase B: Read TPM Public Data
  5. Call virtual method on key object → reads AIK public key from TPM
  6. CryptoUtils::base64_encode(aik_pubkey) → AikPubKey param
  7. Parse ekDefaultCertHandle ("0x01c00002") → uint64
  8. Create TpmPreGeneratedNonVolatile(nv_index=0x01c00002) → for EK cert
  9. Store objects in TpmObjectManager for lifecycle management

Phase C: Build network request params & call Privacy CA
  10. Build option map with short keys like "0", "S", "c", "e", etc.
  11. Call server's virtual method (→ visitor.aik_cert)
  12. ali_trust_tpm_net_aik_cert(visitor, &output_params...)
      → Network call to /aikcert/produce
      → Returns: keyCredentialBlob (var_6e8) and dataCredentialBlob (var_6c8)

Phase D: Process keyCredentialBlob
  13. CryptoUtils::base64_decode(keyCredentialBlob) → raw credential
  14. Save decoded blob to "cipher_aik_key.dat" (timestamped path)

Phase E: TPM2 ActivateCredential
  15. TpmDeviceProxy::run(0x19, {"0": session_ctx, "S": session_file})
      → Command 0x19 (25) = StartAuthSession
  16. TpmDeviceProxy::run(0x1a, {"c": "e", "S": session_file})
      → Command 0x1a (26) = ActivateCredential
      → "c" is credential file, "e" is EK handle
      → TPM proves AIK is co-resident with EK, outputs the wrapped secret

Phase F: Decrypt AIK certificate with activated secret
  17. TpmDeviceProxy::run(0x07, {"C": session, "c": cred_file, "i": input, "P": password, "o": output})
      → Command 7 = Decrypt/Decapsulate operation
      → Writes decrypted secret to "plain_aik_key.dat"
  18. TpmDeviceProxy::run(0x18, {...})
      → Command 0x18 (24) = FlushContext (cleanup)
  19. CryptoUtils::base64_decode(dataCredentialBlob) → raw encrypted blob
  20. FileUtils::read_file_to_string("plain_aik_key.dat") → AES key

Phase G: AES Decrypt the certificate
  21. Parse the decoded dataCredentialBlob:
      - bytes[0:4]   = unknown (version/magic, 4 bytes skipped)
      - bytes[4:20]  = 16-byte AES IV
      - bytes[20:]   = AES ciphertext (encrypted AIK certificate PEM)
  22. CryptoUtils::aes_decrypt(ciphertext, len, aes_key, iv, plaintext, &output_len)
      → aes_key = the activated credential secret from step 17
      → Decrypts to PEM certificate text

Phase H: Cache the AIK certificate
  23. CryptoUtils::trim_certs(decrypted_pem) → clean up whitespace/formatting
  24. ali_trust_elem_init_from_c_str(pem_data) → store in output elem
  25. TpmAttestationImpl::cache_aik_certs(pem_data)
      → split_pem_cert() to separate cert chain
      → Store individual certs as DER in TPM NV indices
```

**KEY INSIGHT:** The AIK certificate is signed server-side and delivered encrypted in the
`dataCredentialBlob`. The `keyCredentialBlob` contains a TPM2_MakeCredential wrapper around
an AES key. Only the real TPM (with the real EK) can unwrap the AES key and decrypt the cert.
This is a textbook Privacy CA implementation with AES envelope encryption.

**There is NO second round-trip.** The entire flow is: one API call → two blobs → TPM unwrap → AES decrypt → PEM cert.

### AIK Certificate Renewal

`TpmAttestationImpl::renew_aik_cert(bool include_chain, _ali_trust_elem& output)` (line 94901):
1. Creates new `TpmPreGeneratedKey` with `aikDefaultKeyHandle`
2. Calls `TpmKey::set_auto_clear()` on the key (marks for cleanup)
3. Creates new `TpmPlatformKey` (re-provisions the platform key)
4. Calls `remove_cached_aik_certs()` to clear old certs from NV storage
5. Then proceeds with the same Privacy CA flow

### AIK Certificate Caching (where the cert ends up)

`TpmAttestationImpl::cache_aik_certs(const string& pem_data)` (line 96508):
1. `CryptoUtils::split_pem_cert()` - splits PEM bundle into individual certs
2. Converts each cert from PEM to DER (`CryptoUtils::cert_pem2der()`)
3. Stores the DER certs in TPM NV indices
4. The split suggests the cert chain may have multiple certs (AIK cert + issuer chain)

### Certificate Expiry Checking

In the outer `ali_trust_tpm_generate_aik_cert()` wrapper (line 68522):
1. First checks `capability(6)` - if supported, goes straight to full cert generation
2. Otherwise: reads cached AIK cert, calls `CryptoUtils::split_pem_cert()`
3. `CryptoUtils::check_cert_expiry(cert, len, &threshold)` with threshold = `time() + 0x15180`
   - 0x15180 = 86400 seconds = **24 hours**
4. If cert expires within 24 hours → trigger full renewal
5. If cert is still valid → use cached version (`ali_trust_elem_move`)
6. This explains why `generate_aik_cert` is called every 30 minutes but doesn't always hit the network

### Quote Generation

`TpmAttestationImpl::generate_quote()` (line 95121):
- PCR selection: `"sha1:0,1,2,3,4,5,6,7,8,9,10+sha256:0,1,2,3,4,5,6,7,8,9,10"` (both SHA-1 and SHA-256 banks, PCRs 0-10)
- Output file: `pcrlist.dat` (timestamped)
- `TpmDeviceProxy::run(0x0b, option_map)` → Command 0x0b (11) = **TPM2_Quote**
- Option keys: `"o"` = output file, `"#"` = PCR selection
- Also handles IMA (Integrity Measurement Architecture) log:
  - Reads `/sys/kernel/security/ima/binary_runtime_measurements`
  - Saves to `ima_log.dat`

### Attestation Submission

`TpmAttestationImpl::attestation()` (line 94126):
- Simple tailcall: `ali_trust_tpm_net_attestation(visitor, result, ...)`
- Delegates entirely to the network layer's `attestation()` method

### TPM Command ID Map (partial, from `TpmDeviceProxy::run` calls)

| CMD ID | Hex | Operation |
|--------|-----|-----------|
| 7 | 0x07 | Decrypt/Decapsulate (via TpmSslOpsImpl) |
| 11 | 0x0B | TPM2_Quote |
| 24 | 0x18 | TPM2_FlushContext |
| 25 | 0x19 | TPM2_StartAuthSession |
| 26 | 0x1a | TPM2_ActivateCredential |
| 29 | 0x1d | (max valid command) |

### `CryptoUtils` Functions Identified

| Function | Purpose |
|----------|---------|
| `base64_encode(data, len, &output_string)` | Base64 encode |
| `base64_decode(string, buf, buf_len, &output_elem)` | Base64 decode |
| `aes_decrypt(ciphertext, len, key, iv, plaintext, &out_len)` | AES decryption |
| `split_pem_cert(pem_bundle, &cert, &chain)` | Split PEM chain |
| `trim_certs(pem_string)` | Clean up PEM formatting |
| `check_cert_expiry(cert, len, &threshold_time)` | Check X.509 expiry |
| `pubkey_from_pem_cert(pem, buf, len, &out_len)` | Extract public key |
| `cert_der2pem(der_elem, &pem_elem)` | DER to PEM conversion |
| `cert_pem2der(pem_elem, &der_elem)` | PEM to DER conversion |
| `hash_sha256(data, len, &output_string)` | SHA-256 hash |

## Open Questions (Updated)

1. ~~**What happens after ActivateCredential?**~~ **RESOLVED.** Full flow documented above.
   The activated credential secret is used as an AES key to decrypt `dataCredentialBlob`,
   which contains the AIK certificate PEM. No second round-trip needed.

2. **Can we extract the AIK cert independently?** The cert is cached in TPM NV indices
   (via `cache_aik_certs`) and also temporarily written to disk as files. The DER-encoded
   certs are stored in NV. With `tpm2_nvread` it should be possible to extract them.

3. **What CA signs the AIK cert?** Still unknown from decompilation alone. The `CertRequest`
   (CSR) parameter in the API suggests the server signs it. The `AIKSS_SERVER_ENDPOINT`
   config option suggests a dedicated AIK Signing Service. The cert chain is split and
   cached, so the response likely includes the full chain (AIK cert + intermediate + root).

4. **Is `ali_trust_generate_plat_cert` useful?** Still needs investigation.

5. **Can we use the quote data for non-interactive verification?** The quote generation
   uses standard TPM2_Quote with SHA-1+SHA-256 banks, PCRs 0-10. If we can get:
   (a) the AIK certificate (from NV or by running the Privacy CA flow ourselves), and
   (b) a raw TPM2_Quote blob (from `tpm2_quote` directly or the `pcrlist.dat` file),
   then we could verify the attestation without going through Alibaba's `/quote` endpoint.
   **This is the key question for vaportpm-verify integration.**

6. **Is `trustclient-opensource` actually open source?** Build path suggests it might be.
   No public repo found yet.

7. **What is the `dataCredentialBlob` format exactly?**
   - bytes[0:4] = unknown (version? magic? AES mode indicator?)
   - bytes[4:20] = 16-byte AES IV
   - bytes[20:] = AES-CBC(?) encrypted PEM certificate
   - Key = TPM2_ActivateCredential output (HMAC-derived secret)

8. **What is the exact AIK key type?** The key handle `0x81010003` is in persistent storage.
   `TpmPreGeneratedKey(handle, algorithm=1)` - what does algorithm=1 map to? (likely RSA 2048)

## Decompilation Artifacts

- `trustagent-hexrays` - Hex-Rays decompilation of `/usr/local/bin/trust-agent`
- `libtrust_network.so.1.0.0.bndb_pseudo_c.txt` - BinaryNinja pseudo-C export of network library (1.1M lines)
- `libtrust_tpm.so.1.0.0.bndb_pseudo_c.txt` - BinaryNinja pseudo-C export of TPM library (210K lines)

### Key functions in `libtrust_network.so` BN export (line numbers):
- `308423` - `TpmHttpVisitor::register_inst`
- `308917` - `TpmHttpVisitor::aik_cert` (fully analyzed)
- `309509` - `TpmHttpVisitor::attestation` (fully analyzed)
- `301886` - `ali_trust_init_tpm_visitor` (endpoint construction)
- `305055` - `TpmPopVisitor::register_inst`
- `305738` - `TpmPopVisitor::aik_cert`
- `306585` - `TpmPopVisitor::attestation`

### Key functions in `libtrust_tpm.so` BN export (line numbers):
- `96987` - `TpmAttestationImpl::generate_aik_cert` (**fully analyzed** - the core Privacy CA flow)
- `94901` - `TpmAttestationImpl::renew_aik_cert`
- `95121` - `TpmAttestationImpl::generate_quote`
- `94126` - `TpmAttestationImpl::attestation` (thin wrapper → network)
- `78153` - `TpmToolsOpsImpl::run` (tpm2-tools dispatch)
- `78218` - `TpmSslOpsImpl::init` (OpenSSL + tpm2-openssl provider)
- `78312` - `TpmSslOpsImpl::run` (OpenSSL-based TPM ops)
- `78795` - `TpmDeviceProxy::run` (command dispatcher)
- `96508` - `TpmAttestationImpl::cache_aik_certs` (NV cert caching)
- `95743` - `TpmAttestationImpl::capability`
- `72827` - `ali_trust_tpm_init_context`
- `68522` - `ali_trust_tpm_generate_aik_cert` (outer wrapper with expiry check)

## Next Steps

- [x] ~~Decompile `libtrust_tpm.so` to understand the ActivateCredential flow~~ **DONE** - full flow documented
- [ ] Look at `TpmPopVisitor::aik_cert` to see if POP path has additional fields/steps
- [ ] Check if `ali_trust_generate_plat_cert` or `ali_trust_generate_app_cert` produce portable certs
- [ ] Search for the `trustclient-opensource` repo
- [ ] **Spin up an Alibaba Cloud ECS instance** to:
  - Capture `/aikcert/produce` and `/quote` traffic
  - Extract the AIK cert from NV (via `tpm2_nvread`)
  - Determine the AIK cert CA chain
  - Test if we can run `tpm2_quote` directly with the AIK key at `0x81010003`
- [ ] Determine if we can replicate the Privacy CA flow from Rust (for vaportpm-verify)
- [ ] Analyze whether the AIK cert + raw TPM2_Quote is sufficient for offline verification

## References

- [Keylime PR #1448](https://github.com/keylime/keylime/pull/1448) - Added Aliyun EK cert to keylime cert store
- [Alibaba Cloud Remote Attestation](https://www.alibabacloud.com/help/en/ecs/user-guide/remote-attestation-service)
- [Alibaba Cloud Trusted Computing](https://www.alibabacloud.com/help/en/ecs/user-guide/overview-of-trusted-computing-capabilities)
- [EAT Profile (TDX only)](https://www.alibabacloud.com/help/en/ecs/user-guide/eat-profile)
- [Create trusted instance (RAM policy with yundun-systrust actions)](https://www.alibabacloud.com/help/en/ecs/user-guide/create-a-security-enhanced-instance)
