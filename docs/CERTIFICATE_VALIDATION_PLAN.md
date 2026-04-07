# Certificate Validation Plan

## Goal

Add certificate-chain validation to the HTTPS certificate viewer so the tool can:

- validate the server certificate for a specific HTTPS URL
- identify which certificates in the chain have problems
- explain why each problem happened
- separate chain-level trust issues from hostname-related TLS issues

## Validation Scope

The feature should report two different result sets.

### 1. TLS Server Validation

This answers:

- can this URL be trusted on the current machine
- does the leaf certificate match the requested hostname
- is the full chain acceptable under the current validation policy

Typical checks:

- hostname match
- certificate validity period
- chain trust
- revocation status
- enhanced key usage for server authentication

### 2. Chain Element Diagnostics

This answers:

- which specific certificate in the chain has a problem
- what problem was found
- whether the problem is an error, warning, or informational note

Typical issues:

- expired certificate
- not yet valid certificate
- untrusted root
- partial chain
- revoked certificate
- offline revocation source
- invalid basic constraints
- invalid key usage or EKU
- invalid name constraints
- cyclic chain

## Key Design Rule

Do not merge server validation and per-certificate diagnostics into one flat result.

Reason:

- a chain can look structurally valid but still fail hostname validation
- a browser-like trust decision depends on machine trust settings
- users need to see both the overall outcome and the exact certificate causing trouble

## Proposed Result Model

### Top-Level Result

A validation run should produce a result object similar to:

- target URL
- target host
- fetch timestamp
- overall server validation status
- hostname validation status
- chain trust status
- revocation mode used
- list of server-level issues
- list of per-certificate diagnostics
- original server chain
- rebuilt validation chain

### Certificate Diagnostic Entry

Each certificate item should eventually include:

- certificate reference or thumbprint
- position in server-provided chain
- position in rebuilt validation chain if different
- status: valid, warning, or error
- list of issues
- whether this certificate was actually used in the rebuilt chain

### Issue Entry

Each issue should include:

- severity: error, warning, info
- code: stable internal identifier
- title: short user-facing summary
- message: readable explanation
- source: chain status, hostname check, policy check, revocation check

## Core Implementation Approach

Use `X509Chain` as the primary validation engine.

### Flow

1. User enters an HTTPS URL.
2. The app fetches the server-provided certificate chain as it does today.
3. The app rebuilds a validation chain from the leaf certificate.
4. Server-provided intermediate certificates are added to `ChainPolicy.ExtraStore`.
5. The app reads:
   - `chain.ChainStatus`
   - `chain.ChainElements`
   - `chain.ChainElements[i].ChainElementStatus`
6. The app separately runs hostname validation against the requested host.
7. The app maps all raw statuses into user-facing diagnostics.

## Important Technical Note

The server-provided chain and the locally rebuilt chain may differ.

Reasons:

- Windows may supplement missing intermediates
- Windows may choose a different trust anchor
- some certificates sent by the server may not be used in the final trust path

Because of that, the tool should preserve both views:

- original chain returned by the server
- rebuilt chain used for validation

## Validation Modes

The tool should be designed with validation modes in mind even if only one mode is implemented first.

### Recommended Modes

#### 1. System Default Validation

Purpose:

- tell the user whether the current Windows machine trusts this server

Characteristics:

- closest to real machine trust behavior
- depends on local trust store and policy

#### 2. Strict Online Validation

Purpose:

- perform a more strict validation with revocation checking enabled

Characteristics:

- stronger validation
- more sensitive to network availability and revocation endpoint failures

#### 3. Offline Structural Validation

Purpose:

- analyze the chain structure without requiring online revocation access

Characteristics:

- stable and fast
- useful for diagnostics
- may not match browser trust decisions exactly

## Recommended Phase 1 Scope

Implement the smallest useful version first.

### Phase 1 Features

- rebuild the chain with `X509Chain`
- inject server intermediates into `ExtraStore`
- report `ChainElementStatus` per certificate
- add explicit hostname matching check
- show overall validation result at the top
- classify issues into error, warning, and info
- do not require strict online revocation checking yet

### Why This First

- high diagnostic value
- relatively low implementation risk
- avoids unstable user experience caused by revocation endpoint failures

## Phase 2 Ideas

- configurable revocation mode
- show rebuilt chain versus server chain side by side
- show whether each server-provided certificate was used
- expose policy settings in UI
- support export of validation report

## Phase 3 Ideas

- custom trust roots
- AIA retrieval for missing intermediates
- richer EKU and policy explanations
- saved validation history
- comparison across multiple hosts

## UI Proposal

### Top Summary Area

Add a summary card above the certificate list.

Suggested fields:

- Server Validation: Valid / Warning / Failed
- Hostname Match: Passed / Failed
- Chain Trust: Passed / Failed
- Revocation: Not checked / Checked / Offline

### Certificate List Enhancements

Each certificate row should show:

- status badge
- issue count
- short summary if any problem exists

Expanded content should show:

- certificate details
- list of diagnostic issues for that certificate
- whether the certificate was used in the rebuilt chain

## Severity Guidance

Use three levels:

- Error: trust decision fails or certificate is clearly invalid
- Warning: validation is incomplete or environment-dependent
- Info: useful diagnostic note without failure

Examples:

- `UntrustedRoot` -> Error
- `PartialChain` -> Error
- `OfflineRevocation` -> Warning
- `NoRevocationCheckConfigured` -> Info

## Mapping Guidance

The raw .NET values should be translated into readable messages.

Example mapping targets:

- `NotTimeValid` -> "Certificate is expired or not yet valid."
- `UntrustedRoot` -> "The root certificate is not trusted on this machine."
- `PartialChain` -> "The chain could not be completed to a trusted root."
- `Revoked` -> "The certificate has been revoked."
- `NotValidForUsage` -> "The certificate is not valid for the required usage."

Hostname mismatch should be represented separately, for example:

- "The leaf certificate does not match the requested host `example.com`."

## Risks and Pitfalls

- hostname validation is not fully represented by `X509Chain` alone
- revocation checking can produce noisy results in restricted networks
- local machine trust settings can make results vary between users
- rebuilt chain ordering may differ from server-returned ordering
- a certificate that appears in the server response may not be part of the final trust path

## Suggested Implementation Order

1. Add result models for server validation and per-certificate diagnostics.
2. Build a validation service around `X509Chain`.
3. Add hostname validation.
4. Map raw statuses into readable diagnostics.
5. Add top-level summary UI.
6. Add per-certificate issue badges and details.
7. Add validation mode options if needed.

## Done Criteria For Phase 1

Phase 1 is complete when:

- the app can validate a fetched chain without crashing
- the app shows overall trust result for the requested URL
- the app marks problematic certificates in the list
- the app explains each problem in readable language
- hostname mismatch is reported separately from chain trust problems
