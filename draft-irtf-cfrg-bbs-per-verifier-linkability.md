%%%
title = "BBS per Verifier Linkability"
abbrev = "BBS per Verifier Linkability"
ipr= "trust200902"
area = "Internet"
workgroup = "CFRG"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Internet-Draft"
value = "draft-irtf-cfrg-bbs-per-verifier-linkability-latest"
status = "informational"

[[author]]
initials = "V."
surname = "Kalos"
fullname = "Vasilis Kalos"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "vasilis.kalos@mattr.global"

[[author]]
initials = "G."
surname = "Bernstein"
fullname = "Greg Bernstein"
#role = "editor"
organization = "Grotto Networking"
  [author.address]
  email = "gregb@grotto-networking.com"

%%%

.# Abstract

The BBS Signatures scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], describes a multi-message digital signature, that supports selectively disclosing the messages through unlinkable presentations, built using zero-knowledge proofs. Each BBS proof reveals no information other than the signed messages that the Prover chooses to disclose in that specific instance. As such, the Verifier (i.e., the recipient) of the BBS proof, may not be able to track those presentations over time. Although in many applications this is desirable, there are use cases that require the Verifier be able to track the BBS proofs they receive from the same Prover. Examples include monitoring the use of access credentials for abnormal activity, monetization etc.. This document presents the use of pseudonyms with BBS proofs.

A pseudonym, is a value that will remain constant each time a Prover presents a BBS proof to the same Verifier, but will be different (and unlinkable), when the Prover interacts with a different Verifier. This provides a way for a recipient (Verifier) to track the presentations intended for them, while also hindering them from tracking the Prover's interactions with other Verifiers.

{mainmatter}

# Introduction

The BBS Signature Scheme, originally described in the academic work by Dan Boneh, Xavier Boyen, and Hovav Shacham [@BBS04], is a signature scheme able to sign multiple messages at once, allowing for selectively disclosing those message while not revealing the signature it self. It does so by creating unlinkable, zero-knowledge proofs-of-knowledge of a signature value on (among other) the disclosed set of messages. More specifically, the BBS Prover, will create a BBS proof that if validated by the Verifier, guarantees that the prover knows a BBS signature on the disclosed messages, guaranteeing the revealed messages authenticity and integrity.

The BBS Proof is by design unlinkable, meaning that given two different BBS proofs, there is no way to tell if they originated from the same BBS signature. This means that if a Prover does not reveal any other identifying information (for example if they are using proxies to hide their IP address etc.), the Verifier of the proof will not be able "track" or "correlate" the different proof presentations  or the Provers activity via cryptographic artifacts. This helps enhance user privacy in applications where the Verifier only needs to know that the Prover is in possession of a valid BBS signature over a list of disclosed messages.

In some applications, however, the Verifier needs to track the presentations made by the Prover over time, as to provide security monitoring, monetization services, configuration persistance etc.. To promote privacy reason, the Prover should not reveal or be bound to a unique identifier that would remain constant across proof presentations to different Verifiers and which could be used to link a Provers interactions with different Verifiers.

The goal of this document is to provide a way for a Verifier to track the proof presentations that are intended for them, while at the same time not allowing the tracking of the Prover's activities with other Verifiers. This is done through the use of pseudonyms. A pseudonym as defined by this document, is a value that will be constant when the Prover presents BBS proofs to the same Verifier, but will change when the Prover interacts with different recipients (with no way to link the two distinct pseudonym values together). This is done by constructing the pseudonym value by combining a unique Verifier identifier with a unique Prover identifier.

To avoid forging requests, the Prover's identifier will be signed by the same BBS signature used to generate the BBS proof. This requires extending the BBS proof generation and verification operations with some additional computations that will be used to prove correctness of the pseudonym, i.e., that it was correctly calculated using the Verifier identifier, as well as, the undisclosed and signed Prover identifier. The Prover identifier MUST be considered secret from the point of view of the Prover, since, if it is revealed, any entity will be able to track the Prover's activity across any Verifiers.

This document will define new BBS Interfaces for use with pseudonyms, however it will not define new ciphersuites. Rather it will re-use the ciphersuites defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

Pseudonyms when used appropriately prevent verifiers from linking prover (proof) presentations between them. We call this verifier-verifier collusion. In addition pseudonyms can be used to prevent the signer from linking prover presentations to a verifier. We call this verifier-signer collusion. This second property is not always desirable in all use cases, for example to allow tracking of purchases a controlled substance by a prover by a central authority while preventing tracking by individual shops.

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

X\[-1\]
: Denotes the last element of the array X

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

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# Key Concepts

A *pseudonym* will be cryptographically generated for each prover-context of usage pair. Its value is dependent on a pseudonym secret (`nym_secret`) and a context identifier (`context_id`).

## Context Identifier

The Context Identifier (`context_id`) is an octet string that represents a specific context of usage, within which, the pseudonym will have a constant value. Context Identifiers can take the form of unique Verifier Identifiers, Session Identifiers etc., depending on the needs of the application. Verifiers will be able to use the pseudonym values to track the presentations generated by a Prover, using the same signature, for that specific context.

## Pseudonyms

The *pseudonym* is a cryptographic value computed by the prover based on the `nym_secret` and the `context_id`. At a high level this is computed by hashing the `context_id` to the elliptic curve group G1 and then multiplying it by the `nym_secret` value. See Section (#pseudonym-calculation-procedure) for details. The pseudonym is sent to a verifier along with the BBS proof.

This document defines a pseudonym as point of the G1 group different from the Identity (`Identity_G1`) or the base point (`BP1`) of G1. A pseudonym remains constant for the same context, when combined with the same signature, but is unique (and unlinkable) across different contexts. In other words, when the Prover presents multiple BBS proofs with a pseudonym to a Verifier, the pseudonym value will be constant across those presentations, if the same `context_id` value is used. When presenting a BBS proof with a pseudonym to a different context, the pseudonym value will be different. Note that since pseudonyms are group points, their value will necessarily change if a different a ciphersuite with a different curve will be used. Serialization and deserialization of the pseudonym point MUST be done using the `point_to_octets_g1` and `octets_to_point_g1` defined by the BBS ciphersuite used (see [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

This document specifies pseudonyms to be BBS Interface specific (see Section TBD of [@!I-D.irtf-cfrg-bbs-signatures] for the definition of the BBS Interface). It is outside the scope of this document to provide a procedure for "linking" the pseudonyms that are used by different Interfaces or that are based on different ciphersuites. An option is for the Prover to present both pseudonyms with the relevant BBS proofs to the Verifier, and upon validation of both, the Verifier to internally link the 2 pseudonyms together.

## Mapping Messages to Scalars

Each BBS Interface defines an operation that will map the inputted messages to scalar values, required by the core BBS operations. Each Interface can use a different mapping procedure, as long as it comforts to the requirements outlined in [@!I-D.irtf-cfrg-bbs-signatures]. For using BBS with pseudonyms, the mapping operation used by the interface is REQUIRED to additionally adhere the following rule;

```
For each set of messages and separate message msg',
if C1 = messages_to_scalars(messages.push(msg')),
and msg_prime_scalar = messages_to_scalars((msg')),
and C2 = messages_to_scalars(messages).push(msg_prime_scalar),
it will always hold that C1 == C2.
```

Informally, the above means that each message is mapped to a scalar independently from all the other messages. For example, if `a = messages_to_scalars((msg_1))` and `b = messages_to_scalars((msg_2))`, then `(a, b) = messages_to_scalars((msg_1, msg_2))`. Its trivial to see that the `messages_to_scalars` operation that is defined in Section TBD of [@!I-D.irtf-cfrg-bbs-signatures], has the required property. That operation will be used by the Interface defined in this document to map the messages to scalars. Note that the above operation (and hence the defined by this document Interface), only accepts messages that are octet strings.

# Pseudonym Calculation Procedure

The following section describes how to calculate a pseudonym from a secret held by the Prover and the public context unique identifier. The pseudonym will be unique for different contexts (e.g., unique Verifier identifiers) and constant under constant inputs (i.e., the same `context_id` and `nym_secret`). The `context_id` is an octet string representing the unique identifier of the context in which the pseudonym will have the same value. The `nym_secret` value is a scalar calculated from secret input provided by the Prover and random (but not secret) input provided by the Signer. This will guarantee uniqueness of the `nym_secret` between different signatures and users.

```
pseudonym = hash_to_curve_g1(context_id) * nym_secret
```

Additionally, the `nym_secret` value will be signed by the BBS Signature. This will bind the pseudonym to a specific signature, held by the Prover. During proof generation, along the normal BBS proof, the Prover will generate a proof of correctness of the pseudonym, i.e., that it has the form described above, and that it was constructed using a `nym_secret` signed by the BBS signature used to generate that proof.

# High Level Procedures and Information Flows

To prevent forgeries in all cases all BBS messages are signed with the inclusion of some form of the provider pseudonym secret (`nym_secret`). In addition the pseudonym is always computed by the prover and sent with the proof to the verifier. While two different variations of signature and proof generation are given below based on the previously discussed unlinkability requirements there MUST be only one verification algorithm for the verifier to use.

1. The Prover computes their input for the `nym_secret` (called `prover_nym`) and retained for use when calculating the `nym_secret` value.
2. The Prover will wrap up in a cryptographic commitment using the *CommitWithNym* procedures of Blind BBS the messages they want to include in the signature (`committed_messages`) and the `prover_nym` value, generating a `commitment_with_proof` and a `secret_prover_blind`.
3. The `commitment_with_proof` is conveyed to the signer which then uses the signing procedures in Section (#signature-generation-and-verification-with-pseudonym) to create a BBS signature and their input for the `nym_secret` value, called `signer_nym_entropy`. They will convey both to the Prover.
4. On receipt of the signature and the `signer_nym_entropy` value, the Prover verifies the signature using the procedure of section (#signature-generation-and-verification-with-pseudonym) and calculates the `nym_secret` value by adding their `prover_nym` secret and the provided `signer_nym_entropy` values.
5. The Prover computes the *pseudonym* based on the `nym_secret` and the pseudonym's context identifier `context_id`.
6. The Prover generates a proof using `nym_secret`, `secret_prover_blind`, `signature`, `messages`, `committed_messages` and the indexes of the messages to be reveled from those two lists (i.e., `disclosed_indexes` and `disclosed_committed_indexes`)  using the procedures of Section (#proof-generation-with-pseudonym).
7. The Prover conveys the `proof` and `pseudonym` to the verifier. The verifier uses the procedure of Section (#proof-verification-with-pseudonym) to verify the proof.

# BBS Pseudonym Interface

The following section defines a BBS Interface that will make use of per-origin pseudonyms where the `nym_secret` value is only known to the prover. The identifier of the Interface, api_id,  is defined as `ciphersuite_id || H2G_HM2S_PSEUDONYM_`, where `ciphersuite_id` the unique identifier of the BBS ciphersuite used, as is defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

The prover create a `nym_secret` value and keeps it secret. Only sending a commitment with the proof of the `nym_secret` that the signer will used when creating the signature.

## Signature Generation and Verification with Pseudonym

### Commitment

This section will describe the steps with which the Signer will generate a blind signature over an array of messages provided (and committed) by the Prover (`committed_messages`) and a pseudonym secret `prover_nym`, also chosen by the Prover. During signature generation, the Signer will provide their own randomness into the pseudonym secret. This will ensure that the pseudonym secret will always be unique, among different signature generation events.

This section will provide a high level description of the required operations, by detailing the modifications required in the relevant BBS blind signature operations, to also consider the use of pseudonyms. The full formal description of the operation can be seen at Appendix. We will reference those operations where appropriate in this section.

Initially, the Prover will chose a set of messages `committed_messages` that they want to be included in the signature, without reveling them to the Signer. They will also choose their part of the pseudonym secret `prover_nym` as a random scalar value.

```
(commitment_with_proof, secret_prover_blind) = CommitWithNym(
                                                   committed_messages,
                                                   prover_nym,
                                                   api_id)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array ("()").
- prover_nym (OPTIONAL), a random scalar value. If not supplied, it
                         defaults to the zero scalar (0).
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commitment_with_proof, secret_prover_blind), a tuple comprising from
                                                an octet string and a
                                                random scalar in that
                                                order.

Procedure:

1. committed_message_scalars = BBS.messages_to_scalars(
                                             committed_messages, api_id)
2. committed_message_scalars.append(prover_nym)

3. blind_generators = BBS.create_generators(
                                  length(committed_message_scalars) + 1,
                                  "BLIND_" || api_id)

4. return Blind.CoreCommit(committed_message_scalars,
                             blind_generators, api_id)
```

### Blind Issuance

The Signer generate a signature from a secret key (SK), the commitment with proof, the signer_nym_entropy and optionally over a `header` and vector of `messages` using
the BlindSignWithNym procedure shown below.

Typically the signer_nym_entropy will be a fresh random scalar, however in the case of
"reissue" of a signature for a prover who wants to keep their same pseudonymous identity this value can be reused for the same prover if desired.

```
BlindSignWithNym(SK, PK, commitment_with_proof, signer_nym_entropy,
                  header, messages)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment_with_proof (OPTIONAL), an octet string, representing a
                                    serialized commitment and
                                    commitment_proof, as the first
                                    element outputted by the CommitWithNym
                                    operation. If not supplied, it
                                    defaults to the empty string ("").
- signer_nym_entropy (REQUIRED), a scalar value.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string ("").
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array ("()").

Deserialization:

1. L = length(messages)

// calculate the number of blind generators used by the commitment,
// if any.
2. M = length(commitment_with_proof)
3. if M != 0, M = M - octet_point_length - octet_scalar_length
4. M = M / octet_scalar_length
5. if M < 0, return INVALID

Procedure:

1.  generators = BBS.create_generators(L + 1, api_id)
2.  blind_generators = BBS.create_generators(M, "BLIND_" || api_id)

3.  commit = Blind.deserialize_and_validate_commit(commitment_with_proof,
                                               blind_generators, api_id)
4.  if commit is INVALID, return INVALID

5.  message_scalars = BBS.messages_to_scalars(messages, api_id)

6.  res = B_calculate(signer_nym_entropy, message_scalars,
                      generators, blind_generators[-1])
7.  if res is INVALID, return INVALID
8.  B = res

9.  blind_sig = Blind.FinalizeBlindSign(SK,
                                  PK,
                                  B,
                                  generators,
                                  blind_generators,
                                  header,
                                  api_id)

10. if blind_sig is INVALID, return INVALID
11. return blind_sig
```

#### Calculate B

The `B_calculate_with_nym` operation is defined as follows,

```
B = B_calculate_with_nym(signer_nym_entropy, generators,
                                                commitment,
                                                nym_generator,
                                                message_scalars)

Inputs:

- signer_nym_entropy (REQUIRED), a scalar.
- generators (REQUIRED), an array of at least one point from the
                         G1 group.
- commitment (REQUIRED), a point from the G1 group
- nym_generator (REQUIRED), a point from the G1 group
- message_scalars (OPTIONAL), an array of scalar values. If not
                              supplied, it defaults to the empty
                              array ("()").

Deserialization:

1. L = length(messages)
2. if length(generators) != L + 1, return INVALID
3. (Q_1, H_1, ..., H_L) = generators

Procedure:

1. B = Q_1 + H_1 * msg_1 + ... + H_L * msg_L + commitment
2. signer_nym_entropy = get_random(1)
3. B = B + nym_generator * signer_nym_entropy
4. If B is Identity_G1, return INVALID
5. return B
```

### Verification and Finalization

The following operation both verifies the generated blind signature, as well as calculating and returning the final `nym_secret`, used to calculate the pseudonym value during proof generation.

This operation uses the `BlindBBS.Verify` function as defined in [Section 4.2.2](https://www.ietf.org/archive/id/draft-kalos-bbs-blind-signatures-01.html#name-blind-signature-verificatio) of the Blind BBS document [@BlindBBS]

```
nym_secret = VerifyFinalizeWithNym(PK,
                      signature,
                      header,
                      messages,
                      committed_messages,
                      prover_nym,
                      signer_nym_entropy,
                      secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- prover_nym (OPTIONAL), scalar value. If not supplied, it defaults to
                         the zero scalar (0).
- signer_nym_entropy (OPTIONAL), a scalar value. If not supplied, it
                                 defaults to the zero scalar (0).
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".

Outputs:

- nym_secret, a scalar value; or INVALID.

Procedure:

1. (message_scalars, generators) = Blind.prepare_parameters(
                                        messages,
                                        committed_messages,
                                        length(messages) + 1,
                                        length(committed_messages) + 2,
                                        secret_prover_blind,
                                        api_id)

2. nym_secret = prover_nym + signer_nym_entropy (modulo r)
3. message_scalars.append(nym_secret)

4. res = BBS.CoreVerify(PK, signature, generators, header,
                                                message_scalars, api_id)

5. if res is INVALID, return INVALID
6. return nym_secret
```

## Proof Generation with Pseudonym

This section defines the `ProofGenWithNym` operations, for calculating a BBS proof with a pseudonym. The BBS proof is extended to include a zero-knowledge proof of correctness of the pseudonym value, i.e., that is correctly calculated using the (undisclosed) pseudonym secret (`nym_secret`), and that is "bound" to the underlying BBS signature (i.e., that the `nym_secret` value is signed by the Signer).

Validating the proof (see `ProofVerifyWithNym` defined in (#proof-verification-with-pseudonym)), guarantees authenticity and integrity of the header, presentation header and disclosed messages, knowledge of a valid BBS signature as well as correctness and ownership of the pseudonym.

To support pseudonyms, the `ProofGenWithNym` procedure takes the pseudonym secret `nym_secret`, as well as the context identifier `context_id`, which the pseudonym will be bounded to.

```
(proof, pseudonym) = ProofGenWithNym(PK,
                        signature,
                        header,
                        ph,
                        nym_secret,
                        context_id,
                        messages,
                        committed_messages,
                        disclosed_indexes,
                        disclosed_commitment_indexes,
                        secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".
- disclosed_commitment_indexes (OPTIONAL), vector of unsigned integers
                                           in ascending order. Indexes
                                           of disclosed committed
                                           messages. If not supplied, it
                                           defaults to the empty array
                                           "()".
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.


Outputs:

- proof, an octet string; or INVALID.

Deserialization:

1. L = length(messages)
2. M = length(committed_messages)
3. if length(disclosed_indexes) > L, return INVALID
4. for i in disclosed_indexes, if i < 0 or i >= L, return INVALID
5. if length(disclosed_commitment_indexes) > M, return INVALID
6. for j in disclosed_commitment_indexes,
                               if i < 0 or i >= M, return INVALID

Procedure:

1. (message_scalars, generators) = Blind.prepare_parameters(
                                         messages,
                                         committed_messages,
                                         L + 1,
                                         M + 2,
                                         secret_prover_blind,
                                         api_id)
2. message_scalars.append(nym_secret)

3. indexes = ()
4. indexes.append(disclosed_indexes)
5. for j in disclosed_commitment_indexes: indexes.append(j + L + 1)

6. (proof, pseudonym) = CoreProofGenWithNym(PK,
                               signature,
                               generators.append(blind_generators),
                               header,
                               ph,
                               context_id,
                               message_scalars.append(committed_message_scalars),
                               indexes,
                               api_id)
7. return (proof, pseudonym)
```

## Proof Verification with Pseudonym

This operation validates a BBS proof with a pseudonym, given the Signer's public key (PK), the proof, the pseudonym, the context identifier that was used to create it, a header and presentation header, the disclosed messages and committed messages as well as the, the indexes those messages had in the original vectors of signed messages. Validating the proof also validates the correctness and ownership by the Prover of the received pseudonym.

```
result = ProofVerifyWithNym(PK,
                                  proof,
                                  header,
                                  ph,
                                  pseudonym,
                                  context_id,
                                  L,
                                  disclosed_messages,
                                  disclosed_committed_messages,
                                  disclosed_indexes,
                                  disclosed_committed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to the empty octet string ("").
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to the empty octet
                 string ("").
- L (OPTIONAL), an integer, representing the total number of Signer
                known messages if not supplied it defaults to 0.
- disclosed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array ("()").
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array ("()").

Parameters:

- api_id, the octet string ciphersuite_id || "H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and "H2G_HM2S_"is
          an ASCII string comprised of 9 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
2. if length(proof) < proof_len_floor, return INVALID
3. U = floor((length(proof) - proof_len_floor) / octet_scalar_length)
4. total_no_messages = length(disclosed_indexes) +
                                 length(disclosed_committed_indexes) + U - 1
5. M = total_no_messages - L

Procedure:

1. (message_scalars, generators) = Blind.prepare_parameters(
                                           disclosed_messages,
                                           disclosed_committed_messages,
                                           L + 1,
                                           M + 1,
                                           NONE,
                                           api_id)

2. indexes = ()
3. indexes.append(disclosed_indexes)
4. for j in disclosed_commitment_indexes: indexes.append(j + L + 1)

5. result = CoreProofVerifyWithNym(PK,
                                    proof,
                                    pseudonym,
                                    context_id,
                                    generators,
                                    header,
                                    ph,
                                    message_scalars,
                                    indexes,
                                    api_id)
6. return result
```

# Core Operations

## Core Proof Generation

This operations computes a BBS proof and a zero-knowledge proof of correctness of the pseudonym in "parallel" (meaning using common randomness), as to both create a proof that the pseudonym was correctly calculated using an undisclosed value that the Prover knows (i.e., the `nym_secret` value), but also that this value is "signed" by the BBS signature (the last undisclosed message). As a result, validating the proof guarantees that the pseudonym is correctly computed and that it was computed using the Prover identifier that was included in the BBS signature.

The operation uses the `BBS.ProofInit` and `BBS.ProofFinalize` operations defined in [Section 3.7.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html#name-proof-initialization) and [Section 3.7.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html#name-proof-finalization) correspondingly of [@!I-D.irtf-cfrg-bbs-signatures], the `PseudonymProofInit` operation defined in (#pseudonym-proof-generation-initialization) and the `ProofWithPseudonymChallengeCalculate` defined in (#challenge-calculation).

```
(proof, pseudonym) = CoreProofGenWithNym(PK,
                                  signature,
                                  pseudonym,
                                  verifier_id,
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
- pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- context_id (REQUIRED), an octet string, representing the unique proof
                          Verifier identifier.
- generators (REQUIRED), vector of points in G1.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- message_scalars (OPTIONAL), a vector of scalars representing the
                              messages. If not supplied, it defaults to
                              the empty array "()" must include the
                              nym_secret scalar as last element.
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
4.  L = length(message_scalars)
5.  R = length(disclosed_indexes)
6.  (i1, ..., iR) = disclosed_indexes
7.  if R > L - 1, return INVALID, Note: we never reveal the nym_secret.
8.  U = L - R

// Note: nym_secret is last message and is not revealed.
9.  undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
10. (i1, ..., iR) = disclosed_indexes
11. (j1, ..., jU) = undisclosed_indexes
12. disclosed_messages = (message_scalars[i1], ..., message_scalars[iR])
13. undisclosed_messages = (message_scalars[j1], ...,
                                                    message_scalars[jU])

ABORT if:

1. for i in disclosed_indexes, i < 0 or i > L - 1, // Note: nym_secret
                                                   // is the Lth message
                                                   // and not revealed.

Procedure:

1. random_scalars = calculate_random_scalars(5+U)
2. init_res = BBS.ProofInit(PK,
                        signature_res,
                        header,
                        random_scalars,
                        generators,
                        message_scalars,
                        undisclosed_indexes,
                        api_id)
3. if init_res is INVALID, return INVALID

4. pseudonym_init_res = PseudonymProofInit(context_id,
                                           message_scalars[-1],
                                           random_scalars[-1])
5. if pseudonym_init_res is INVALID, return INVALID
6. pseudonym = pseudonym_init_res[0]

7. challenge = ProofWithPseudonymChallengeCalculate(init_res,
                                                    pseudonym_init_res,
                                                    disclosed_indexes,
                                                    disclosed_messages,
                                                    ph,
                                                    api_id)
8. proof = BBS.ProofFinalize(init_res, challenge, e_value,
                                   random_scalars, undisclosed_messages)
9. return (proof, pseudonym)
```

## Core Proof Verification

This operation validates a BBS proof that also includes a pseudonym. Validating the proof, other than the correctness and integrity of the revealed messages, the header and the presentation header values, also guarantees that the supplied pseudonym was correctly calculated, i.e., that it was produced using the Verifier's identifier and the signed (but undisclosed) Prover's identifier, following the operation defined in (#pseudonym-calculation-procedure).

The operation uses the `BBS.ProofVerifyInit` operation defined [Section 3.7.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html#name-proof-verification-initiali) of [@!I-D.irtf-cfrg-bbs-signatures], the `PseudonymProofVerifyInit` operation defined in (#pseudonym-proof-verification-initialization) and the `ProofWithPseudonymChallengeCalculate` operation defined in (#challenge-calculation).

```
result = CoreProofVerifyWithNym(PK,
                                      proof,
                                      pseudonym,
                                      context_id,
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
- pseudonym (REQUIRED), A point of G1, different from the Identity of
                        G1, as outputted by the CalculatePseudonym
                        operation.
- context_id (REQUIRED), an octet string, representing the unique proof
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

1. init_res = BBS.ProofVerifyInit(PK, proof_result, header, generators,
                                    messages, disclosed_indexes, api_id)

2. pseudonym_init_res = PseudonymProofVerifyInit(pseudonym,
                                                 context_id,
                                                 commitments[-1],
                                                 cp)
3. if pseudonym_init_res is INVALID, return INVALID

4. challenge = ProofWithPseudonymChallengeCalculate(init_res,
                                                    pseudonym_init_res,
                                                    disclosed_indexes,
                                                    messages,
                                                    ph,
                                                    api_id)
5. if cp != challenge, return INVALID
6. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
7. return VALID
```

## Pseudonym Proof Generation Utilities

### Pseudonym Proof Generation Initialization

```
pseudonym_init_res = PseudonymProofInit(context_id,
                                          nym_secret, random_scalar)

Inputs:

- context_id (REQUIRED), an octet string
- nym_secret (REQUIRED), a scalar value
- random_scalar (REQUIRED), a scalar value

Outputs:

- a tuple consisting of three elements from the G1 group, or INVALID.

Procedure:

1. OP = hash_to_curve_g1(context_id, api_id)
2. pseudonym = OP * nym_secret
3. Ut = OP * random_scalar
4. if pseudonym == Identity_G1 or Ut == Identity_G1, return INVALID
5. return (pseudonym, OP, Ut)
```

### Pseudonym Proof Verification Initialization

```
pseudonym_init_res = PseudonymProofVerifyInit(pseudonym,
                                              context_id,
                                              nym_secret_commitment
                                              proof_challenge)

Inputs:

- pseudonym (REQUIRED), an element of the G1 group.
- context_id (REQUIRED), an octet string.
- nym_secret_commitment (REQUIRED), a scalar value.
- proof_challenge (REQUIRED), a scalar value.

Outputs:

- a tuple consisting of three elements from the G1 group, or INVALID.

Procedure:

1. OP = hash_to_curve_g1(context_id)
2. Uv = OP * nym_secret_commitment - pseudonym * proof_challenge
3. if Uv == Identity_G1, return INVALID
4. return (pseudonym, OP, Uv)
```


# Utility Operations

## Challenge Calculation

```
challenge = ProofWithPseudonymChallengeCalculate(init_res,
                                                 pseudonym_init_res,
                                                 i_array,
                                                 msg_array,
                                                 ph, api_id)

Inputs:
- init_res (REQUIRED), vector representing the value returned after
                       initializing the proof generation or verification
                       operations, consisting of 5 points of G1 and a
                       scalar value, in that order.
- pseudonym_init_res (REQUIRED), vector representing the value returned
                                 after initializing the pseudonym proof,
                                 consisting of 3 points of G1.
- i_array (REQUIRED), array of non-negative integers (the indexes of
                      the disclosed messages).
- msg_array (REQUIRED), array of scalars (the disclosed messages after
                        mapped to scalars).
- ph (OPTIONAL), an octet string. If not supplied, it must default to
                 the empty octet string ("").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- challenge, a scalar.

Definitions:

1. challenge_dst, an octet string representing the domain separation
                  tag: api_id || "H2S_" where "H2S_" is an ASCII string
                  comprised of 4 bytes.

Deserialization:

1. R = length(i_array)
2. (i1, ..., iR) = i_array
3. (msg_i1, ..., msg_iR) = msg_array
4. (Abar, Bbar, D, T1, T2, domain) = init_res
5. (pseudonym, OP, Ut) = pseudonym_init_res

ABORT if:

1. R > 2^64 - 1 or R != length(msg_array)
2. length(ph) > 2^64 - 1

Procedure:
1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar,
                                   D, T1, T2, pseudonym, OP, Ut, domain)
2. c_octs = serialize(c_arr) || I2OSP(length(ph), 8) || ph
3. return hash_to_scalar(c_octs, challenge_dst)
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

<reference anchor="BlindBBS" target="https://datatracker.ietf.org/doc/draft-kalos-bbs-blind-signatures/">
 <front>
   <title> Blind BBS Signatures</title>
   <author><organization>IETF</organization></author>
 </front>
</reference>
