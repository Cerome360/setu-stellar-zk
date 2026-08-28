pragma circom 2.2.0;

// Auditor-side recomputation helper (witness-only; no proving, no secrets).
// The auditor knows the disclosed cleartext (recipientId, purpose, value), the
// viewingKey shared with them, and the public nullifierHash. They recompute the
// two bound hashes and check them against the receipt's public signals [2],[3].
// They never learn nullifier or secret.
//
// DOMAIN SEPARATION: mirrors disclosure.circom exactly.
//   discloseHash = Poseidon255(1, recipientId, purpose, value)
//   auditorTag   = Poseidon255(2, viewingKey, nullifierHash)

include "poseidon255.circom";

template AuditorRecompute() {
    signal input recipientId;
    signal input purpose;
    signal input value;
    signal input viewingKey;
    signal input nullifierHash;

    signal output discloseHash;
    signal output auditorTag;

    // Domain-separated discloseHash: tag 1
    component dh = Poseidon255(4);
    dh.in[0] <== 1;
    dh.in[1] <== recipientId;
    dh.in[2] <== purpose;
    dh.in[3] <== value;
    discloseHash <== dh.out;

    // Domain-separated auditorTag: tag 2
    component at = Poseidon255(3);
    at.in[0] <== 2;
    at.in[1] <== viewingKey;
    at.in[2] <== nullifierHash;
    auditorTag <== at.out;
}

component main = AuditorRecompute();
