# Disclosure test fixture

These files are a frozen Groth16 fixture for the current domain-separated
`circuits/disclosure.circom`, generated from
`circuits/disclosure_private.json` with a local, test-only
`snarkjs` trusted setup. They are stored in the exact byte format consumed by
`zk::{VerificationKey, Proof, PublicSignals}` on Soroban:

- `disclosure_vk.hex`: disclosure verification key
- `disclosure_proof.hex`: proof for the fixture's private inputs
- `disclosure_public_signals.hex`: `[nullifierHash, commitment, discloseHash, auditorTag]`
- `disclosure_recipient_tampered.hex`: signals derived after changing `recipientId`
- `disclosure_purpose_tampered.hex`: signals derived after changing `purpose`

The fixture is test data only. Do not use its verification key or trusted
setup in a deployed contract. Regenerate the snarkjs artifacts with
`scripts/disclosure_e2e.sh`, then convert each artifact with
`stellar-circom2soroban` before replacing these files.
