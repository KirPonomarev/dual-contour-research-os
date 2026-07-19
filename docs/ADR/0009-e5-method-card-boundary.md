# ADR 0009: E5 declassified MethodCard boundary

Status: accepted for the S35 frozen scope.

E5 uses a separate additive contract catalog so the frozen Core catalog is not
rewritten. A `MethodCard` contains controlled method codes and public/sanitized
references only. It cannot contain raw evidence, targets, strategies, holdouts,
free-form prompts, credentials or domain conclusions.

Only a domain-owned `domain-declassification-authority` may issue the preceding
`DeclassificationReceipt`. Bridge validates that receipt and may project the
result; it cannot mint domain authority. `SHADOW_UNAPPLIED`, D2/D3, an expired
receipt, a mismatched draft digest or any forbidden metadata fails closed.

A MethodCard grants transfer eligibility only. Recipient adoption, scientific
truth, promotion, policy mutation, deployment and live action remain absent and
require their separate domain or human authority receipts.
