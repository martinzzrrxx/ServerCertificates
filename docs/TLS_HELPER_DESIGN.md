# TLS Helper Design

## Goal

Provide a reliable way to capture the actual server-sent certificate chain for
modern TLS connections, including `TLS 1.3`.

The helper exists because the main WPF app can rebuild a local validation chain,
but it cannot reliably recover the peer-sent chain through `SslStream` alone.

## Why A Helper Is Needed

Current limitations:

- `SslStream` can complete the handshake, but it does not expose a guaranteed
  "peer-sent chain" view
- raw TLS parsing works only as a partial experiment for `TLS 1.2`
- `TLS 1.3` encrypts the certificate message after `ServerHello`
- accurate `Validated Only / Not Used` results depend on a trustworthy
  server-sent chain

Conclusion:

- the app should stop treating handshake-side reconstruction as a long-term
  source of truth
- a dedicated TLS helper should own server-sent chain capture

## Recommended Shape

Use a small standalone helper executable.

Recommended characteristics:

- local process, launched on demand by the WPF app
- single responsibility: perform TLS handshake capture
- return results as JSON over stdout
- no UI
- short-lived process per request

Why an executable instead of an in-process library:

- cleaner separation between UI code and TLS implementation
- easier to replace implementation details later
- easier to debug independently
- safer if native/OpenSSL integration is needed

## Recommended Implementation Direction

Preferred approach:

- implement the helper on top of a mature TLS stack that can expose the peer
  certificate chain directly

Practical options:

1. Native helper using OpenSSL
2. Native helper using another mature TLS library with equivalent visibility

Not recommended as the main solution:

- continuing to hand-parse TLS records in managed code
- relying on `SslStream` callback chain data as the server-sent source

## Process Contract

The main app launches the helper with a small request payload and reads one JSON
response.

### Invocation Model

Suggested command pattern:

```text
tls-helper.exe --input-json
```

Then write one JSON request to stdin and read one JSON response from stdout.

Alternative:

- pass request data through arguments

Stdin/stdout JSON is preferred because:

- cleaner escaping
- easier future expansion
- avoids long command lines

## Request Model

Suggested request JSON:

```json
{
  "host": "example.com",
  "port": 443,
  "sniHost": "example.com",
  "connectTimeoutMs": 10000,
  "supportedTlsVersions": ["TLS1.2", "TLS1.3"]
}
```

### Required Fields

- `host`
- `port`
- `sniHost`

### Optional Fields

- `connectTimeoutMs`
- `supportedTlsVersions`

## Response Model

Suggested success response:

```json
{
  "success": true,
  "fetchSource": "TlsHelper",
  "negotiatedTlsVersion": "TLS1.3",
  "cipherSuite": "TLS_AES_128_GCM_SHA256",
  "serverSentChain": [
    {
      "index": 0,
      "subject": "CN=example.com",
      "issuer": "CN=Example Intermediate",
      "thumbprint": "ABC123",
      "derBase64": "..."
    }
  ],
  "notes": []
}
```

Suggested failure response:

```json
{
  "success": false,
  "fetchSource": "TlsHelper",
  "errorCode": "HandshakeFailed",
  "errorMessage": "TLS handshake failed before the certificate chain was captured.",
  "notes": [
    "Remote alert: handshake_failure"
  ]
}
```

## Certificate Payload Format

Use DER encoded certificate bytes serialized as Base64.

Reason:

- compact
- deterministic
- easy to hydrate into `X509Certificate2`
- avoids PEM parsing complexity inside the WPF layer

Suggested per-certificate fields:

- `index`
- `subject`
- `issuer`
- `thumbprint`
- `derBase64`

Only `derBase64` is strictly required for downstream processing. The rest are
convenience fields for debugging and logging.

## Error Model

Define stable helper error codes.

Suggested first set:

- `DnsResolutionFailed`
- `ConnectionFailed`
- `HandshakeFailed`
- `CertificateCaptureUnavailable`
- `InvalidResponse`
- `InternalError`

The helper should always prefer:

- stable machine-readable `errorCode`
- short human-readable `errorMessage`

## Main App Integration

The WPF app should treat the helper as the preferred chain source.

Suggested fetch order:

1. `TLS Helper`
2. fallback chain capture

Meaning:

- if helper succeeds:
  - use helper output as the server-sent chain
  - mark source as reliable
- if helper fails:
  - fall back to current `SslStream` path
  - mark source as fallback / non-authoritative

## Main App Changes Needed

Add a small orchestration layer in the main app:

- `TlsHelperClient`
  - starts the helper
  - sends request JSON
  - parses response JSON
  - converts certificates to `X509Certificate2`

Update the current fetch model:

- add a helper-based fetch source enum value such as `TlsHelper`
- keep existing fallback values

No UI redesign is required for this step. The existing chain source hint can
reuse the new source value directly.

## Logging Guidance

The helper should write only JSON to stdout.

If logging is needed:

- write diagnostics to stderr
- keep stdout reserved for the response payload

This avoids parsing ambiguity in the main app.

## Security Boundaries

The helper should:

- not install certificates
- not mutate trust stores
- not write files unless explicitly asked
- not execute arbitrary shell commands

Its responsibility is limited to:

- connect
- handshake
- capture chain
- report metadata

## Recommended Delivery Order

### Phase A

- finalize helper request/response schema
- add `TlsHelperClient` contract in the WPF app
- keep helper implementation mocked or stubbed

### Phase B

- implement a minimal real helper using a mature TLS library
- return server-sent chain for `TLS 1.2` and `TLS 1.3`

### Phase C

- wire helper into the app as the preferred fetch source
- keep `SslStream` fallback for resilience

### Phase D

- add helper-specific diagnostics and better source reporting

## Success Criteria

The helper is successful when:

- it can reliably capture server-sent chains for `TLS 1.3`
- the main app can compare helper output against `X509Chain` rebuild output
- `Validated Only / Not Used` become trustworthy for modern hosts
