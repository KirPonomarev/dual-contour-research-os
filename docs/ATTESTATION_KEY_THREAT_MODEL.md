# Selected receipt attestation key threat model

The S34 attestation layer signs only selected high-value receipt files. It does
not replace their existing integrity profile, does not grant authority and does
not promote or apply any outcome.

## Key boundary

- Git stores only the Ed25519 public key and its lifecycle metadata.
- The private key is operator-owned, mode `0600`, outside the repository and is
  passed to the signing tool only as an explicit path.
- The tool never prints, serializes, snapshots or copies private key bytes.
- A signature binds the SHA-256 of the exact receipt bytes and the receipt's
  already frozen `payload_sha256`; S34 does not introduce JCS.

## Rotation and revocation

At most two keys may be active during a seven-day rotation overlap. A new key
must be added before the old key is retired. Unknown, inactive, substituted or
revoked keys fail closed. Revocation does not rewrite old receipts; verification
reports them rejected for the selected scope.

## Anchoring

The attestation document is first pushed to a non-force Git commit on the
configured GitHub remote. A separate AnchorReceipt binds the attestation digest
to that exact commit URL and SHA. Missing anchoring yields `WAIT_ANCHOR`;
invalid, non-ancestor or mismatched anchoring yields `REJECTED_ANCHOR`.

## Compromise response

Revoke the key in the public registry, disable further signing, retain the
compromised evidence for audit, rotate to a new external key, and re-attest only
after the underlying receipt and authority chain are independently revalidated.
No automated rollback, deploy or canonical mutation follows from compromise.
