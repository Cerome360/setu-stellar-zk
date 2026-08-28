pragma circom 2.2.0;

// Setu selective-disclosure receipt circuit.
// Lives inside the fork so it reuses Poseidon255 (BLS12-381) + circom2soroban,
// and is byte-compatible with the pool's on-chain hashing.
//
// NOT in upstream soroban-privacy-pools. Their ASP proves "my deposit is in a
// clean set." This proves the complementary auditor-facing statement:
//   "The on-chain withdrawal with this nullifierHash spends this exact deposit
//    leaf, whose committed value is disclosed alongside prover-asserted
//    recipient/purpose context."
// Per-transaction reveal, no pool-wide unlink, secret never exposed.
//
// Commitment scheme matched to circuits/commitment.circom:
//   nullifierHash = Poseidon255(nullifier)
//   precommitment = Poseidon255(nullifier, secret)
//   commitment    = Poseidon255(value, label, precommitment)
//
// PRIVACY NOTE: this receipt deliberately links nullifierHash <-> commitment,
// which the pool otherwise keeps unlinkable. That link is revealed ONLY to the
// verifier of this proof (the auditor). The receipt must be transmitted
// privately; auditorTag lets an auditor recognize receipts intended for the
// viewing key they hold. It is not an authenticated auditor identity.
//
// DOMAIN SEPARATION (issue #4):
//   discloseHash = Poseidon255(DISCLOSE_DOMAIN, recipientId, purpose, value)
//   auditorTag   = Poseidon255(AUDITOR_DOMAIN, viewingKey, nullifierHash)
//
//   DISCLOSE_DOMAIN = 1 (stable constant, never reused for other hashes)
//   AUDITOR_DOMAIN  = 2 (stable constant, never reused for other hashes)
//
//   These prevent hash confusion if future circuits or product contexts add
//   new Poseidon invocations over the same field elements. The domain tags
//   are deterministic, circuit-internal, and do not need to be agreed upon
//   off-chain — both the prover and auditor embed them identically.

include "poseidon255.circom";

template Disclosure() {
    // ---- PUBLIC ----
    signal input nullifierHash;   // also the on-chain spent marker
    signal input commitment;      // on-chain leaf; auditor checks get_commitments()
    signal input discloseHash;    // = Poseidon255(DISCLOSE_DOMAIN, recipientId, purpose, value)
    signal input auditorTag;      // = Poseidon255(AUDITOR_DOMAIN, viewingKey, nullifierHash)

    // ---- PRIVATE ----
    signal input value;
    signal input label;
    signal input nullifier;
    signal input secret;
    signal input recipientId;     // prover-asserted beneficiary/context hash
    signal input purpose;         // prover-asserted purpose code
    signal input viewingKey;      // shared with the chosen auditor

    // ---- DOMAIN SEPARATORS (stable constants) ----
    // Never change these values; they tag the Poseidon invocation to prevent
    // cross-circuit or cross-product hash confusion.
    signal discloseDomain;        // = 1
    signal auditorDomain;         // = 2
    discloseDomain <-- 1;
    auditorDomain  <-- 2;

    // 1. Tie the receipt to a real, settled withdrawal.
    component nh = Poseidon255(1);
    nh.in[0] <== nullifier;
    nullifierHash === nh.out;

    // 2. Reconstruct the commitment -> proves knowledge of this coin opening.
    component pre = Poseidon255(2);
    pre.in[0] <== nullifier;
    pre.in[1] <== secret;

    component com = Poseidon255(3);
    com.in[0] <== value;
    com.in[1] <== label;
    com.in[2] <== pre.out;
    commitment === com.out;

    // 3. Bind disclosed fields with domain separation.
    //    The domain tag (1) prevents hash confusion with other Poseidon calls.
    //    recipientId/purpose are hashed context, but v1 does not prove they
    //    were committed at deposit time.
    component dh = Poseidon255(4);
    dh.in[0] <== discloseDomain;
    dh.in[1] <== recipientId;
    dh.in[2] <== purpose;
    dh.in[3] <== value;
    discloseHash === dh.out;

    // 4. Bind the receipt to a viewing key, specific to this withdrawal, with
    //    domain separation. The domain tag (2) prevents confusion with other
    //    Poseidon calls. Uses the PUBLIC nullifierHash so the auditor who
    //    knows viewingKey and nullifierHash can independently recompute and
    //    confirm the tag.
    component at = Poseidon255(3);
    at.in[0] <== auditorDomain;
    at.in[1] <== viewingKey;
    at.in[2] <== nullifierHash;
    auditorTag === at.out;
}

component main {public [nullifierHash, commitment, discloseHash, auditorTag]} = Disclosure();
