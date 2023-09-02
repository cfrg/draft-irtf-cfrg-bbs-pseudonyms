%%%
title = "BBS per Verifier Linkability"
abbrev = "BBS per Verifier Linkability"
ipr= "trust200902"
area = "Internet"
workgroup = "CFRG"

[seriesInfo]
name = "Internet-Draft"
value = "draft-vasilis-bbs-per-verifier-linkability-latest"
status = "informational"

[[author]]
initials = "V."
surname = "Kalos"
fullname = "Vasilis Kalos"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "vasilis.kalos@mattr.global"

%%%

.# Abstract

TODO Abstract


{mainmatter}

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Scheme Definition

## Signature Generation and Verification

The Issuer of the BBS signature will include a constant unique prover identifier (`pid`) as one of the signed messages. The format of that identifier is outside the scope of this document. An options is to use a pseudo random generator to return 32 random octets. The `pid` value MUST be the last one in the set of messages.

More specifically, the Signer to generate a signature from a secret key (SK), a constant prover identifier (`pid`) and optionally over a `header` and or a vector of `messages`, MUST execute the following steps,

```
1. messages = messages.push(pid)
2. signature = Sign(SK, PK, header, messages)
```

Where `Sign` is defined in [Section 3.4.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-generation-sign) of [@!I-D.irtf-cfrg-bbs-signatures].

To verify the above `signature`, for a given `pid`, `header` and vector of `messages`, against a supplied public key (`PK`), the Prover MUST execute the following steps,

```
1. messages = messages.push(pid)
2. signature = Verify(PK, signature, header, messages)
```

The `Verify` operation is defined in [Section 3.4.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-verification-veri) of [@!I-D.irtf-cfrg-bbs-signatures].

## Proof Generation with Pseudonym

This section defines operations for generating a pseudonym, as well as using it to calculate a BBS proof. The BBS proof is extended to include a zero-knowledge proof of correctness of the pseudonym value, i.e., that is correctly calculated using the (undisclosed) id of the Prover (`pid`), and that is "bound" to the underlying BBS signature (i.e., that the `pid` value is signed by the Signer).

### Calculate Pseudonym

The following operation describes how to calculate a pseudonym from the Prover's and the Verifier's unique identifiers (IDs), as well as a BBS interface identifier (`api_id`, see TBD). The pseudonym will be unique for different Verifier and interface IDs and constant under constant inputs (i.e., the same `verifier_id`, `pid` and `api_id` values).

```
pseudonym = CalculatePseudonym(verifier_id, pid)

Inputs:

- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- pid (REQUIRED), an octet string, representing the unique Prover
                  identifier.

Outputs:

- pseudonym, A point of G1, different from the Identity of G1; or
             INVALID.

Parameters:

- api_id, the octet string ciphersuite_id || "H2G_HM2S_VERIFIER_ID_",
          where ciphersuite_id is defined by the ciphersuite and
          "H2G_HM2S_VERIFIER_ID_" is an ASCII string comprised of
          9 bytes.
- hash_to_curve_g1,

Procedure:

1. OP = hash_to_curve_g1(verifier_id)
2. if OP is INVALID, return INVALID
3. pid_scalar = messages_to_scalars((pid), api_id)
4. return OP * pid_scalar
```

### Proof Generation

Thi operation computes a BBS proof with a pseudonym, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. The BBS proof is extended to also include a zero-knowledge proof of correctness of the pseudonym, meaning that it is correctly calculated, using a signed Prover identifier.

Validating the proof (see ProofVerify defined in TBD) guarantees authenticity and integrity of the header and disclosed messages, knowledge of a valid BBS signature as well as correctness and ownership of the pseudonym.

This operation makes use of CoreProofGen as defined in TBD.

```
proof = ProofGen(PK, signature, Pseudonym, verifier_id, pid, header,
                                        ph, messages, disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- Pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- pid (REQUIRED), an octet string, representing the unique Prover
                  identifier.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- api_id, the octet string ciphersuite_id || "H2G_HM2S_VERIFIER_ID_",
          where ciphersuite_id is defined by the ciphersuite and
          "H2G_HM2S_VERIFIER_ID_" is an ASCII string comprised of
          9 bytes.

Outputs:

- proof, an octet string; or INVALID.

Procedure:

1. messages = messages.push(pid)
2. message_scalars = messages_to_scalars(messages, api_id)
3. generators = create_generators(length(messages)+1, PK, api_id)

4. proof = CoreProofGen(PK,
                        signature,
                        Pseudonym,
                        verifier_id,
                        generators,
                        header,
                        ph,
                        message_scalars,
                        disclosed_indexes,
                        api_id)

5. if proof is INVALID, return INVALID
6. return proof
```

## Proof Verification with Pseudonym

The ProofVerify operation validates a BBS proof with a pseudonym, given the Signer's public key (PK), a signature, the pseudonym and the Verifier's identifier that was used to create it, a header and presentation header values, the disclosed messages and the indexes those messages had in the original vector of signed messages. Validating the proof also validates the correctness and ownership by the Prover of the received pseudonym.

This operation makes use of CoreProofVerify as defined in TBD.

```
result = ProofVerify(PK, proof, Pseudonym, verifier_id, header, ph,
                     disclosed_messages,
                     disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- Pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- api_id, the octet string ciphersuite_id || "H2G_HM2S_VERIFIER_ID_",
          where ciphersuite_id is defined by the ciphersuite and
          "H2G_HM2S_VERIFIER_ID_" is an ASCII string comprised of
          9 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
2. if length(proof) < proof_len_floor, return INVALID
3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
4. R = length(disclosed_indexes)

Procedure:

1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
2. generators = create_generators(U + R + 1, PK, api_id)

3. result = CoreProofVerify(PK,
                            proof,
                            Pseudonym,
                            verifier_id,
                            generators,
                            header,
                            ph,
                            message_scalars,
                            disclosed_indexes,
                            api_id)
4. return result
```

# Core Operations

This section defines the core operations used by the ProofGen and ProofVerify operations defined in TBD and TBD correspondingly. This operations are handling the main mathematical operations required to compute and validate the BBS with pseudonym proof.

## Core Proof Gen

This operations computes a BBS proof and a zero-knowledge proof of correctness of the pseudonym in "parallel" (meaning using common randomness), as to not only create a proof that the pseudonym was correctly calculated using a undisclosed value that the Prover knows, but also that this value is "signed" by the BBS Signer (the last undisclosed message). As a result, validating the proof guarantees that the pseudonym is correctly computed and that it was computed using the Prover Identifier the Signer included in the BBS signature.

```
proof = CoreProofGen(PK,
                     signature,
                     Pseudonym,
                     verifier_id,
                     pid,
                     generators,
                     header,
                     ph,
                     messages,
                     disclosed_indexes,
                     api_id)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- Pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- generators (REQUIRED), vector of points in G1.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of scalars representing the messages.
                       If not supplied, it defaults to the empty
                       array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Outputs:

- proof, an octet string; or INVALID.

Deserialization:

1.  signature_result = octets_to_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e) = signature_result
4.  L = length(messages)
5.  R = length(disclosed_indexes)
6.  (i1, ..., iR) = disclosed_indexes
7.  if R > L, return INVALID
8.  U = L - R
9.  undisclosed_indexes = range(1, L) \ disclosed_indexes
10. disclosed_messages = (messages[i1], ..., messages[iR])

ABORT if:

1. for i in disclosed_indexes, i < 1 or i > L - 1

Procedure:

1.  random_scalars = calculate_random_scalars(3+U)
2.  init_res = ProofInit(PK,
                        signature_res,
                        header,
                        random_scalars,
                        generators,
                        messages,
                        undisclosed_indexes,
                        api_id)
3.  if init_res is INVALID, return INVALID

4.  OP = hash_to_curve_g1(verifier_id)
5.  pid~ = random_scalars[3+U] // last element of random_scalars
6.  U = OP * pid~
7.  pseudonym_init_res = (Pseudonym, OP, U)

8.  challenge = ProofChallengeCalculate(init_res,
                                        pseudonym_init_res,
                                        disclosed_indexes,
                                        disclosed_messages,
                                        ph,
                                        api_id)

9.  proof = ProofFinalize(challenge, e, random_scalars, messages,
                                                    undisclosed_indexes)
10. return proof_to_octets(proof)
```

## Core Proof Verify

This operation validates an extended BBS proof that also includes a pseudonym.

```
result = CoreProofVerify(PK,
                         proof,
                         Pseudonym,
                         verifier_id,
                         generators,
                         header,
                         ph,
                         disclosed_messages,
                         disclosed_indexes,
                         api_id)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- Pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- generators (REQUIRED), vector of points in G1.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of scalars representing the
                                 messages. If not supplied, it defaults
                                 to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_result = octets_to_proof(proof)
2. if proof_result is INVALID, return INVALID
3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
4. W = octets_to_pubkey(PK)
5. if W is INVALID, return INVALID
6. (i1, ..., iR) = disclosed_indexes

Procedure:

1.  init_res = ProofVerifyInit(PK, proof_result, header, generators,
                                    messages, disclosed_indexes, api_id)

2.  OP = hash_to_curve_g1(verifier_id)
3.  U = length(commitments)
4.  pid^ = commitments[U] // last element of commitments
5.  Uv = OP * pid^ - Pseudonym * cp
6.  pseudonym_init_res = (Pseudonym, OP, Uv)

7.  challenge = ProofChallengeCalculate(init_res,
                                        pseudonym_init_res,
                                        disclosed_indexes,
                                        messages,
                                        ph,
                                        api_id)
8.  if cp != challenge, return INVALID
9.  if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
10. return VALID
```

# Utility Operations

## Challenge Calculation
```
challenge = ProofChallengeCalculate(init_res, pseudonym_init_res,
                                                 i_array, msg_array, ph)

Inputs:
- init_res (REQUIRED), vector representing the value returned after
                       initializing the proof generation or verification
                       operations, consisting of 3 points of G1 and a
                       scalar value, in that order.
- pseudonym_init_res (REQUIRED), vector representing the value returned
                                 after initializing the pseudonym proof,
                                 consisting of 3 points of G1.
- i_array (REQUIRED), array of non-negative integers (the indexes of
                      the disclosed messages).
- msg_array (REQUIRED), array of scalars (the disclosed messages after
                        mapped to scalars).
- ph (OPTIONAL), an octet string. If not supplied, it must default to the
                 empty octet string ("").

Outputs:

- challenge, a scalar.

Deserialization:

1. R = length(i_array)
2. (i1, ..., iR) = i_array
3. (msg_i1, ..., msg_iR) = msg_array
4. (Abar, Bbar, C, domain) = init_res
5. (Pseudonym, OP, U) = pseudonym_init_res

ABORT if:

1. R > 2^64 - 1 or R != length(msg_array)
2. length(ph) > 2^64 - 1

Procedure:

1. c_arr = (Abar, Bbar, C, Pseudonym, OP, U, R, i1, ..., iR,
                                            msg_i1, ..., msg_iR, domain)
2. c_octs = serialize(c_array)
3. return hash_to_scalar(c_octs || I2OSP(length(ph), 8) || ph)
```

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


{backmatter}

# Acknowledgments

TODO acknowledge.
