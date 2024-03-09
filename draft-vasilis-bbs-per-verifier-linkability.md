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

The BBS Signatures scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], describes a multi-message digital signature, that supports selectively disclosing the messages through unlinkable presentations, built using zero-knowledge proofs. Each BBS proof reveals no information other than the signed messages that the Prover chooses to disclose in that specific instance. As such, the Verifier (i.e., the recipient) of the BBS proof, may not be able to track those presentations over time. Although in many applications this is desirable, there are use cases where that require the Verifier be able to track the BBS proofs they receive from the same Prover. Examples include monitoring the use of access credentials for abnormal activity, monetization etc.. This document presents the use of pseudonyms with BBS proofs.

A pseudonym, is a value that will remain constant each time a Prover presents a BBS proof to the same Verifier, but will be different (and unlinkable), when the Prover interacts with a different Verifier. This provides a way for a recipient (Verifier) to track the presentations intended for them, while also hindering them from tracking the Prover's interactions with other Verifiers.

{mainmatter}

# Introduction

The BBS Signature Scheme, originally described in the academic work by Dan Boneh, Xavier Boyen, and Hovav Shacham [@BBS04], is a signature scheme able to sign multiple messages at once, allowing for selectively disclosing those message while not revealing the signature it self. It does so by creating unlinkable, zero-knowledge proofs-of-knowledge of a signature value on (among other) the disclosed set of messages. More specifically, the BBS Prover, will create a BBS proof that if validated by the Verifier, guarantees that the prover knows a BBS signature on the disclosed messages, guaranteeing the revealed messages authenticity and integrity.

The BBS Proof is by design unlinkable, meaning that given two different BBS proofs, there is no way to tell if they originated from the same BBS signature. This means that if a Prover does not reveal any other identifying information (for example if they are using proxies to hide their IP address etc.), the Verifier of the proof will not be able "track" or "correlate" the different proof presentations  or the Provers activity via cryptographic artifacts. This helps enhance user privacy in applications where the Verifier only needs to know that the Prover is in possession of a valid BBS signature over a list of disclosed messages.

In some applications, however, the Verifier needs to track the presentations made by the Prover over time, as to provide security monitoring, monetization services, configuration persistance etc.. To promote privacy reason, the Prover should not reveal or be bound to a unique identifier that would remain constant across proof presentations to different Verifiers and which could be used to link a Provers interactions with different Verifiers.

The goal of this document is to provide a way for a Verifier to track the proof presentations that are intended for them, while at the same time not allowing the tracking of the Prover's activities with other Verifiers. This is done through the use of Pseudonyms. A pseudonym as defined by this document, is a value that will be constant when the Prover presents BBS proofs to the same Verifier, but will change when the Prover interacts with different recipients (with no way to link the two distinct pseudonym values together). This is done by constructing the pseudonym value by combining a unique Verifier identifier with a unique Prover identifier.

To avoid forging requests, the Prover's identifier will be signed by the same BBS signature used to generate the BBS proof. This requires extending the BBS proof generation and verification operations with some additional computations that will be used to prove correctness of the pseudonym, i.e., that it was correctly calculated using the Verifier identifier, as well as, the undisclosed and signed Prover identifier. The Prover identifier MUST be considered secret from the point of view of the Prover, since, if it is revealed, any entity will be able to track the Prover's activity across any Verifiers.



This document will define a new BBS Interface for use with pseudonyms, however it will not define new ciphersuites. Rather it will re-use the ciphersuites defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

## Terminology

The following terminology is used throughout this document:

SK
: The secret key for the signature scheme.

PK
: The public key for the signature scheme.

L
: The total number of signed messages.

R
: The number of message indexes that are disclosed (revealed) in a proof-of-knowledge of a signature.

U
: The number of message indexes that are undisclosed in a proof-of-knowledge of a signature.

scalar
: An integer between 0 and r-1, where r is the prime order of the selected groups, defined by each ciphersuite (see also [Notation](#notation)).

generator
: A valid point on the selected subgroup of the curve being used that is employed to commit a value.

signature
: The digital signature output.

presentation\_header (ph)
: A payload generated and bound to the context of a specific spk.

INVALID, ABORT
: Error indicators. INVALID refers to an error encountered during the Deserialization or Procedure steps of an operation. An INVALID value can be returned by a subroutine and handled by the calling operation. ABORT indicates that one or more of the initial constraints defined by the operation are not met. In that case, the operation will stop execution. An operation calling a subroutine that aborted must also immediately abort.

## Notation

The following notation and primitives are used:

a || b
: Denotes the concatenation of octet strings a and b.

I \\ J
: For sets I and J, denotes the difference of the two sets i.e., all the elements of I that do not appear in J, in the same order as they were in I.

X\[a..b\]
: Denotes a slice of the array `X` containing all elements from and including the value at index `a` until and including the value at index `b`. Note when this syntax is applied to an octet string, each element in the array `X` is assumed to be a single byte.

range(a, b)
: For integers a and b, with a <= b, denotes the ascending ordered list of all integers between a and b inclusive (i.e., the integers "i" such that a <= i <= b).

length(input)
: Takes as input either an array or an octet string. If the input is an array, returns the number of elements of the array. If the input is an octet string, returns the number of bytes of the inputted octet string.

Terms specific to pairing-friendly elliptic curves that are relevant to this document are restated below, originally defined in [@!I-D.irtf-cfrg-pairing-friendly-curves].

E1, E2
: elliptic curve groups defined over finite fields. This document assumes that E1 has a more compact representation than E2, i.e., because E1 is defined over a smaller field than E2. For a pairing-friendly curve, this document denotes operations in E1 and E2 in additive notation, i.e., P + Q denotes point addition and x \* P denotes scalar multiplication.

G1, G2
: subgroups of E1 and E2 (respectively) having prime order r.

GT
: a subgroup, of prime order r, of the multiplicative group of a field extension.

e
: G1 x G2 -> GT: a non-degenerate bilinear map.

r
: The prime order of the G1 and G2 subgroups.

BP1, BP2
: base (constant) points on the G1 and G2 subgroups respectively.

Identity\_G1, Identity\_G2, Identity\_GT
: The identity element for the G1, G2, and GT subgroups respectively.

hash\_to\_curve\_g1(ostr, dst) -> P
: A cryptographic hash function that takes an arbitrary octet string as input and returns a point in G1, using the hash\_to\_curve operation defined in [@!I-D.irtf-cfrg-hash-to-curve] and the inputted dst as the domain separation tag for that operation (more specifically, the inputted dst will become the DST parameter for the hash\_to\_field operation, called by hash\_to\_curve).

point\_to\_octets\_g1(P) -> ostr, point\_to\_octets\_g2(P) -> ostr
: returns the canonical representation of the point P for the respective subgroup as an octet string. This operation is also known as serialization.

octets\_to\_point\_g1(ostr) -> P, octets\_to\_point\_g2(ostr) -> P
: returns the point P for the respective subgroup corresponding to the canonical representation ostr, or INVALID if ostr is not a valid output of the respective point\_to\_octets_g\* function. This operation is also known as deserialization.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Preliminaries

## Pseudonyms

This document defines a pseudonym as point of the G1 group different from the Identity (`Identity_G1`) or the base point (`BP1`) of G1. A pseudonym remains constant for each Prover and Verifier pair, but is unique (and unlinkable) across different Provers or Verifiers. In other words, when the Prover presents multiple BBS proofs with a pseudonym to a Verifier, the pseudonym value will be constant across those presentations. When presenting a BBS proof with a pseudonym to another Verifier however, the pseudonym value will be different. Note that since pseudonyms are group points, their value will necessarily change if a different a ciphersuite with a different curve will be used. This document specifies pseudonyms to be BBS Interface specific (see Section TBD of [@!I-D.irtf-cfrg-bbs-signatures] for the definition of the BBS Interface). It is outside the scope of this document to provide a procedure for "linking" the pseudonyms that are used by different Interfaces or that are based on different ciphersuites. An option is for the Prover to present both Pseudonyms with the relevant BBS proofs to the Verifier, and upon validation of both, the Verifier to internally link the 2 pseudonyms together.

## Prover Identifier

Each pseudonym is constructed from a unique Prover Identifier (`pid`), which is an octet string that MUST be at least 32 octets long. The `pid` value will be the last message signed by the BBS signature. In this document the Prover Identifier is chosen by the BBS Signer. This gives the Signer the ability to track the Prover even when they present BBS proofs with pseudonyms to different Verifiers. To avoid this threat, the Prover can choose and "commit" the `pid` value themselves, using Blind BBS Signatures, as defined in TBD. In any case, the `pid` value MUST be the last signed message. It also MUST unique across different Provers with very high probability. Additionally, it MUST be indistinguishable from a random value, drawn from the uniform distribution over the space of all octet strings that are at least 32 octets long. Such value could be generated from a cryptographically secure pseudo-random number generator. See [@DRBG] for requirements and suggestions on generating randomness.

As mentioned above, the pseudonym value is defined as a point of the G1 group. Serialization and deserialization of the pseudonym point MUST be done using the `point_to_octets_g1` and `octets_to_point_g1` defined by the BBS ciphersuite used (see [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

## Mapping Messages to Scalars

Each BBS Interface defines an operation that will map the inputted messages to scalar values, required by the core BBS operations. Each Interface can use a different mapping procedure, as long as it comforts to the requirements outlined in TBD. For using BBS with pseudonyms, the mapping operation used by the interface is REQUIRED to additionally adhere the following rule;

```
For each set of messages and separate message msg',
if C1 = messages_to_scalars(messages.push(msg')),
and msg_prime_scalar = messages_to_scalars((msg')),
and C2 = messages_to_scalars(messages).push(msg_prime_scalar),
it will always hold that C1 == C2.
```

Informally, the above means that each message is mapped to a scalar independently from all the other messages. For example, if `a = messages_to_scalars((msg_1))` and `b = messages_to_scalars((msg_2))`, then `(a, b) = messages_to_scalars((msg_1, msg_2))`. Its trivial to see that the `messages_to_scalars` operation that is defined in Section TBD of [@!I-D.irtf-cfrg-bbs-signatures], has the required property. That operation will be used by the Interface defined in this document to map the messages to scalars. Note that the above operation (and hence the defined by this document Interface), only accepts messages that are octet strings.

# BBS with Pseudonym Interface

The following section defines a BBS Interface that will make use of per-origin pseudonyms. The identifier of the Interface is defined as `ciphersuite_id || H2G_HM2S_PSEUDONYM_`, where `ciphersuite_id` the unique identifier of the BBS ciphersuite used, as is defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]). Each BBS Interface MUST define operations to map the inputted messages to scalar values and to create the generators set, required by the core operations. The inputted messages to the defined in this document BBS Interface will be mapped to scalars using the `messages_to_scalars` operation defined in Section TBD of [@!I-D.irtf-cfrg-bbs-signatures]. The generators will be created using the `create_generators` operation defined in Section TBD of [@!I-D.irtf-cfrg-bbs-signatures].

This document also defines 2 alternative core proof generation and verification operations (see (#core-operations)), to accommodate the use of pseudonyms. Those operations will be used by the defined proof generation and verification Interface operations, in place of the `CoreProofGen` and `CoreProofVerify` operations defined in Section TBD of [@!I-D.irtf-cfrg-bbs-signatures].

## Signature Generation and Verification

The Issuer of the BBS signature will include a constant unique prover identifier (`pid`) as one of the signed messages. The format of that identifier is outside the scope of this document. An options is to use a pseudo random generator to return 32 random octets. The `pid` value MUST be the last one in the set of signed messages.

More specifically, the Signer to generate a signature from a secret key (SK), a constant Prover identifier (`pid`) and optionally over a `header` and or a vector of `messages`, MUST execute the following steps,

```
1. messages = messages.push(pid)
2. signature = Sign(SK, PK, header, messages)
```

Where `Sign` is defined in [Section 3.4.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-generation-sign) of [@!I-D.irtf-cfrg-bbs-signatures], instantiated with the `api_id` parameter set to the value `ciphersuite_id || H2G_HM2S_PSEUDONYM_`, where `ciphersuite_id` the unique identifier of the ciphersuite.

To verify the above `signature`, for a given `pid`, `header` and vector of `messages`, against a supplied public key (`PK`), the Prover MUST execute the following steps,

```
1. messages = messages.push(pid)
2. signature = Verify(PK, signature, header, messages)
```

The `Verify` operation is defined in [Section 3.4.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-verification-veri) of [@!I-D.irtf-cfrg-bbs-signatures], instantiated with the `api_id` parameter set to the value `ciphersuite_id || H2G_HM2S_PSEUDONYM_`, where `ciphersuite_id` the unique identifier of the ciphersuite.

## Proof Generation with Pseudonym

This section defines operations for generating a pseudonym, as well as using it to calculate a BBS proof. The BBS proof is extended to include a zero-knowledge proof of correctness of the pseudonym value, i.e., that is correctly calculated using the (undisclosed) id of the Prover (`pid`), and that is "bound" to the underlying BBS signature (i.e., that the `pid` value is signed by the Signer).

### Calculate Pseudonym

The following operation describes how to calculate a pseudonym from the Prover's and the Verifier's unique identifiers (IDs), as well as a BBS Interface identifier (`api_id`, see TBD). The pseudonym will be unique for different Verifier and interface IDs and constant under constant inputs (i.e., the same `verifier_id`, `pid` and `api_id` values).

```
pseudonym = CalculatePseudonym(verifier_id, pid, api_id)

Inputs:

- verifier_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- pid (REQUIRED), an octet string, representing the unique Prover
                  identifier.
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").


Outputs:

- pseudonym, A point of G1, different from the Identity_G1, BP1 and P1
             (see the Parameters of this operation); or INVALID.

Parameters:

- hash_to_curve_g1, the hash_to_curve operation defined by the Hash to
                    Curve suite determined by the ciphersuite, through
                    the hash_to_curve_suite parameter.
- P1, fixed point of G1, defined by the ciphersuite.

Procedure:

1. OP = hash_to_curve_g1(verifier_id, api_id)
2. if OP is INVALID, return INVALID
3. if OP == Identity_G1 or OP == BP1 or OP == P1, return INVALID
3. pid_scalar = messages_to_scalars((pid), api_id)
4. return OP * pid_scalar
```

### Proof Generation

Thi operation computes a BBS proof with a pseudonym, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. The BBS proof is extended to also include a zero-knowledge proof of correctness of the pseudonym, meaning that it is correctly calculated, using a signed Prover identifier and the supplied Verifier's ID.

Validating the proof (see `ProofVerifyWithPseudonym` defined in (#proof-verification-with-pseudonym)), guarantees authenticity and integrity of the header, presentation header and disclosed messages, knowledge of a valid BBS signature as well as correctness and ownership of the pseudonym.

This operation makes use of `CoreProofGenWithPseudonym` as defined in (#core-proof-generation).

```
proof = ProofGenWithPseudonym(PK,
                              signature,
                              Pseudonym,
                              verifier_id,
                              pid,
                              header,
                              ph,
                              messages,
                              disclosed_indexes)

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

- api_id, the octet string ciphersuite_id || "H2G_HM2S_PSEUDONYM_",
          where ciphersuite_id is defined by the ciphersuite and
          "H2G_HM2S_PSEUDONYM_" is an ASCII string comprised of
          9 bytes.

Outputs:

- proof, an octet string; or INVALID.

Procedure:

1. message_scalars = messages_to_scalars(messages, api_id)
2. pid_scalar = messages_to_scalars((pid), api_id)
3. generators = create_generators(length(messages) + 2, PK, api_id)

4. proof = CoreProofGenWithPseudonym(PK,
                                     signature,
                                     Pseudonym,
                                     verifier_id,
                                     pid_scalar,
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

This operation validates a BBS proof with a pseudonym, given the Signer's public key (PK), the proof, the pseudonym and the Verifier's identifier that was used to create it, a header and presentation header, the disclosed messages and lastly, the indexes those messages had in the original vector of signed messages. Validating the proof also validates the correctness and ownership by the Prover of the received pseudonym.

This operation makes use of `CoreProofVerifyWithPseudonym` as defined in (#core-proof-verification).

```
result = ProofVerifyWithPseudonym(PK,
                                  proof,
                                  Pseudonym,
                                  verifier_id,
                                  header,
                                  ph,
                                  disclosed_indexes,
                                  disclosed_messages)

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

- api_id, the octet string ciphersuite_id || "H2G_HM2S_PSEUDONYM_",
          where ciphersuite_id is defined by the ciphersuite and
          "H2G_HM2S_PSEUDONYM_" is an ASCII string comprised of
          9 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_len_floor = 2 * octet_point_length + 3 * octet_scalar_length
2. if length(proof) < proof_len_floor, return INVALID
3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
4. R = length(disclosed_indexes)
5. L = U + R

Procedure:

1. message_scalars = messages_to_scalars(disclosed_messages, api_id)
2. generators = create_generators(L + 1, PK, api_id)

3. result = CoreProofVerifyWithPseudonym(PK,
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

This section defines the core operations used by the `ProofGenWithPseudonym` and `ProofVerifyWithPseudonym` operations defined in (#proof-generation-with-pseudonym) and (#proof-verification-with-pseudonym) correspondingly. Those operations are handling the main mathematical procedures required to compute and validate the BBS with pseudonym proof.

## Core Proof Generation

This operations computes a BBS proof and a zero-knowledge proof of correctness of the pseudonym in "parallel" (meaning using common randomness), as to both create a proof that the pseudonym was correctly calculated using an undisclosed value that the Prover knows (i.e., the `pid` value), but also that this value is "signed" by the BBS signature (the last undisclosed message). As a result, validating the proof guarantees that the pseudonym is correctly computed and that it was computed using the Prover identifier that was included in the BBS signature.

The operation uses the `ProofInit` and `ProofFinalize` operations defined in TBD and the `ProofWithPseudonymChallengeCalculate` defined in (#challenge-calculation).

```
proof = CoreProofGenWithPseudonym(PK,
                                  signature,
                                  Pseudonym,
                                  verifier_id,
                                  pid_scalar,
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
- pid_scalar (REQUIRED), a scalar value, representing the unique Prover
                         identifier after it is mapped to a scalar.
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

4.  messages = messages.push(pid_scalar)
5.  L = length(messages)
6.  R = length(disclosed_indexes)
7.  (i1, ..., iR) = disclosed_indexes
8.  if R > L, return INVALID
9.  U = L - R
10. undisclosed_indexes = range(1, L) \ disclosed_indexes
11. disclosed_messages = (messages[i1], ..., messages[iR])

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

8.  challenge = ProofWithPseudonymChallengeCalculate(init_res,
                                                     pseudonym_init_res,
                                                     disclosed_indexes,
                                                     disclosed_messages,
                                                     ph,
                                                     api_id)

9.  proof = ProofFinalize(challenge, e, random_scalars, messages,
                                                    undisclosed_indexes)
10. return proof_to_octets(proof)
```

## Core Proof Verification

This operation validates a BBS proof that also includes a pseudonym. Validating the proof, other than the correctness and integrity of the revealed messages, the header and the presentation header values, also guarantees that the supplied pseudonym was correctly calculated, i.e., that it was produced using the Verifier's identifier and the signed (but undisclosed) Prover's identifier, following the `CalculatePseudonym` operation defined in (#calculate-pseudonym).

The operation uses the `ProofVerifyInit` operation defined in TBD and the `ProofWithPseudonymChallengeCalculate` defined in (#challenge-calculation).

```
result = CoreProofVerifyWithPseudonym(PK,
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
6. R = length(disclosed_indexes)
7. (i1, ..., iR) = disclosed_indexes

ABORT if:

1. for i in disclosed_indexes, i < 1 or i > R + length(commitments) - 1

Procedure:

1.  init_res = ProofVerifyInit(PK, proof_result, header, generators,
                                    messages, disclosed_indexes, api_id)

2.  OP = hash_to_curve_g1(verifier_id)
3.  U = length(commitments)
4.  pid^ = commitments[U] // last element of the commitments
5.  Uv = OP * pid^ - Pseudonym * cp
6.  pseudonym_init_res = (Pseudonym, OP, Uv)

7.  challenge = ProofWithPseudonymChallengeCalculate(init_res,
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
challenge = ProofWithPseudonymChallengeCalculate(init_res,
                                                 pseudonym_init_res,
                                                 i_array,
                                                 msg_array,
                                                 ph)

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

# Ciphersuites

This document does not define new BBS ciphersuites. Its ciphersuite defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]) can be used to instantiate the operations of the described scheme.

# IANA Considerations

This document has no IANA actions.


{backmatter}

# Acknowledgments

TODO acknowledge.


<reference anchor="BBS04" target="https://link.springer.com/chapter/10.1007/978-3-540-28628-8_3">
 <front>
   <title>Short Group Signatures</title>
   <author initials="D." surname="Boneh" fullname="Dan Boneh">
    </author>
    <author initials="X." surname="Boyen" fullname="Xavier Boyen">
    </author>
    <author initials="H." surname="Shacham" fullname="Hovav Scacham">
    </author>
    <date year="2004"/>
 </front>
 <seriesInfo name="In" value="Advances in Cryptology"/>
 <seriesInfo name="pages" value="41-55"/>
</reference>

<reference anchor="DRBG" target="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">
 <front>
   <title>Recommendation for Random Number Generation Using Deterministic Random Bit Generators</title>
   <author><organization>NIST</organization></author>
 </front>
</reference>
