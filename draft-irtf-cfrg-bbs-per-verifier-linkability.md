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

The BBS Signatures scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], describes a multi-message digital signature, that supports selectively disclosing the messages through unlinkable presentations, built using zero-knowledge proofs. Each BBS proof reveals no information other than the signed messages that the Prover chooses to disclose in that specific instance. As such, the Verifier (i.e., the recipient) of the BBS proof, may not be able to track those presentations over time. Although in many applications this is desirable, there are use cases that require the Verifier be able to track the BBS proofs they receive from the same Prover. Examples include monitoring the use of access credentials for abnormal activity, assertion of pseudonymous identity, monetization, etc.. This document provides a mechanism for binding prover secret material for pseudonym creation to a BBS signature and shows how to use this bound information for the creation of context dependent pseudonyms in BBS proofs.

{mainmatter}

# Introduction

The BBS Signature Scheme, originally described in the academic work by Dan Boneh, Xavier Boyen, and Hovav Shacham [@BBS04], is a signature scheme able to sign multiple messages at once, allowing for selectively disclosing those message while not revealing the signature it self. It does so by creating unlinkable, zero-knowledge proofs-of-knowledge of a signature value on (among other) the disclosed set of messages. More specifically, the BBS Prover, will create a BBS proof that if validated by the Verifier, guarantees that the prover knows a BBS signature on the disclosed messages, guaranteeing the revealed messages authenticity and integrity.

The BBS Proof is by design unlinkable, meaning that given two different BBS proofs, there is no way to tell if they originated from the same BBS signature. This means that if a Prover does not reveal any other identifying information (for example if they are using proxies to hide their IP address etc.), the Verifier of the proof will not be able "track" or "correlate" the different proof presentations  or the Provers activity via cryptographic artifacts. This helps enhance user privacy in applications where the Verifier only needs to know that the Prover is in possession of a valid BBS signature over a list of disclosed messages.

In some applications, however, a Verifier needs to track the presentations made by the Prover over time, as to provide security monitoring, monetization services, configuration persistance etc.. In other applications a Prover may wish to assert a pseudonymous identity associated with a signature from an issuer. To promote privacy, the Prover should not be forced to reveal or be bound to a unique identifier that would remain constant across proof presentations to different Verifiers and which could be used to link a Provers interactions with different Verifiers.

The goal of this document is to provide a way for a Verifier to track the proof presentations that are intended for them, while at the same time not allowing the tracking of the Prover's activities with other Verifiers. This is done through the use of a cryptographic pseudonyms.

A cryptographic pseudonym, or pseudonym for short, as defined by this document, is a value that will be computed from two parts. One part is the pseudonym secret value (nym_secret) which is known only to the prover and a context value (context_id) that must be known by both prover and verifier. The pseudonym value is computed in such a way that it is computationally infeasable to link to pseudonyms to the same pseudonym secret, i.e., holder for two different context values.

## Pseudonyms Bound to BBS Signatures

The BBS signature scheme is based on a three party model of *signer* (aka issuer), *prover* (aka user or holder), and *verifier*.  A *prover* obtains a BBS signature from a *signer* over a list of BBS *messages* and presents a BBS proof (of signature) along with a selectively disclosed subset of the BBS *messages* to a verifier. Each BBS proof generated is unlinkable to other BBS proofs derived from the same signature and from the BBS signature itself. If the disclosed subset of BBS *messages* are not linkable then the presentations cannot be linked.

BBS pseudonyms extend the BBS signature scheme to "bind" a "pseudonym secret" to a BBS signature retaining all the properties of the BBS signature scheme: (a) a short signature over multiple messages, (b) selective disclosure of a subset of messages from *prover* to *verifier*, (c) unlinkable proofs.

In addition BBS pseudonyms provide for:

1. A essentially unique identifier, a pseudonym, bound to a proof of signature whose linkability is under the control of the *prover* in conjunction with a *verifier* via the selection of a "context". Such a pseudonym can be used when a *prover* revisits a *verifier* to allow a *verifier* to recognize the prover when they return or for the *prover* to assert their pseudonomous identity when visiting a *verifier*
2. Assurance of per *signer* uniqueness of the "pseudonym secret", i.e., the *signer* assures that the pseudonyms that will be guaranteed by the signature have not been used with any other signature issued by the signer (unless a signature is intentionally reissued).
3. The *signer* cannot track the *prover* presentations to *verifiers* based on pseudonym values.
4. Colluding *verifiers* sharing BBS proofs with pseudonyms cannot link proofs or pseudonyms across "contexts".

To realize the above feature set we embed a two part pseudonym capability into the BBS signature scheme. The pseudonym's cryptographic value will be computed from a secret part, which we call the *nym_secret* and a part that is public or at least shared between the *prover* and one or more *verifiers*. The public part we call the *context_id*. The pseudonym is calculated from these two pieces using discrete exponentiation. This is similar to the computations in [@Lys00] and [@ABC14]. The pseudonym is presented to the *verifier* along with a ZKP that the *prover* knows the *nym_secret* and used it and the *context_id* to compute the pseudonym value. A similar proof mechanism was used in [@Lys00].

To bind a pseudonym to a BBS signature we have the *signer* utilzed Blind BBS signatures and essentially sign over a commitment to the *nym_secret*. Hence only a prover that knows the *nym_secret* can generate a BBS proof from the signature (and also generate the pseudonym proof).

As in [@Lys00] we are concerned with the possibility of a dishonest user and hence require that that the *nym_secret* = *prover_nym* + *signer_nym_entropy* be the sum of two parts where the *prover_nym* is a provers secret and only sent to the *signer* in a binding and hiding commitment. The *signer_nym_entropy* is "blindly added" in by the *signer* during the signing procedure and sent back to the *prover* along with the signature. Note the order of operations. The *prover* chooses their (random) *prover_nym* and commits to it. They then send the commitment along with a ZKP proof that the *prover_nym* makes this commitment. The *signer* verifies the commitment to the *prover_nym* then generates the *signer_nym_entropy* and "blindly adds" it to the *prover_nym* during the signature process. Note that this can be done since we sign over the commitment and we know the generator for the commitment.

This document will define new BBS Interfaces for use with pseudonyms, however it will not define new ciphersuites. Rather it will re-use the ciphersuites defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

## Cryptographic Pseudonyms: A Short History

The discussion of cryptographic pseudonyms for privacy preservation has a long history, with Chaum's 1985 popular article “Security without identification: transaction systems to make big brother obsolete” [@Chaum85] addressesing many of the features of such systems such as unlinkability and constraints on their use such as one pseudonym per organization and accountability for pseudonym use. Although Chaum's proposal makes use of different cryptographic primitives than we will use here, one can see similarities in the use of both secret and "public" information being combined to create a cryptographic pseudonym.

Lysyanskaya's 2000 paper [@Lys00] also addresses the unlinkable aspects of pseudonyms but also provides protections against dishonest users. In addition they provide practical contructions similar to those used in our draft based on discrete logarithm and sigma protocol based ZKPs. Finally as part of the ABC4Trust project [@ABC14] three flavors of pseudonyms were defined:

1. *Verifiable pseudonyms* are pseudonyms derived from an underlying secret key.
2. *Certified pseudonyms* are verifiable pseudonyms derived from a secret key that also underlies an issued credential.
3. *Scope-exclusive pseudonyms* are verifiable pseudonyms that are guaranteed to be unique per scope string and per secret key.

The BBS based pseudonyms in our draft are aimed primarily at providing the functionality of the pseudonym flavors 2. and 3. above.

## BBS Pseudonym Example Applications

### Certifiable Pseudonyms

In this case the *prover* gets to choose and assert a "pseudonymous identity" bound to a signature (credential) from an *issuer*.

The *prover* can choose this "pseudonymous identity" through its choice of a *context_id* that will then be shared with along with the cryptographic pseudonym with a *verifier*. Note that the combination of (*context_id*, *cryptographic_pseudonym*) forms the "psedonymous identity" that is bound to the BBS signature. By changing the *context_id* the *prover* can choose a new "pseudonymous identity" however, within the cryptographic limitations of BBS and the pseudonym computaions, no other prover should be able to assert this "pseudonymous identity". This is confirmed by the *verifier* during BBS pseudonym proof validation and utilizes the *signers* public key.

The mechanims in this draft permit the *issuer* to guarantee that the *nym_secret* is essentially unique to and by the issuer, though not known to the issuer. Further enhancing the "pseudonymous identity".

The *prover* and no one else without the *nym_secret* and signature can produce a proof that they "own" the "pseudonymous identity".

### Scope Exclusive Pseudonyms

In this case a *verifier* or group of *verifiers* needs to know if the same *prover* is presenting a BBS proof of signature along with some selectively disclosed information (BBS messages) on subsequent presentations.

We assume that no linkable information is contained in the disclosed messages or information that can be obtained from other layers in the application/communications stack.

To do this a *verifier* requires that the *prover* use a *context_id* that the *verifier* specifies. In this case the *verifier* can use the *cryptographic pseudonym* to link subsequent proof presentations from the same *prover*. However, *cryptographic pseudonyms* from *verifiers* that specify different *context_ids* cannot, within the cryptographic assumptions of the pseudonym computation be linked to each other. This provides the *verifier* with limited linkability to a *prover* and a *prover* unlinkability across *verifiers* using **different** *context_ids*.

### Scope Exclusive Pseudonyms with Monitoring

In this case third party monitoring of interactions between *prover* and *verifier* is required.

For example (completely ficticious) suppose the signature (credential) certifies that the *prover* is qualified to purchase and store some type of controlled substance, e.g., a class of potentially hazardous chemicals. To avoid price fixing or leakage of secret chemical formulas the *prover* purchases these chemicals under a *verifier* (vendor) specific pseudonym. Which prevents the different vendors from colluding on prices or seeing all the chemicals being purchase by a given prover.

However for public safety, hording prevention, etc... verifiers (vendors) are required to report all purchase to a 3rd party monitor along with the pseudonym under which the purchases were made (and the *context_id* of the vendor). To allow the third party monitor to link these pseudonyms to a *prover*, the prover would be required to reveal the *nym_secret* associated with this credential only to the *monitor*.

Note that this is why this specification separates *nym_secrets* from other secrets (blind BBS messages) that might be used to "bind" a credential to a *prover*.

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

## Prover Pseudonym Secret

The prover pseudonym secret (`nym_secrets`) is a vector of one or more secret scalars used in the pseudonym calculation procedure of (#pseudonym-calculation-procedure). The *prover* needs to keep this information secret as its name indicates. To prevent a *prover* that may have stolen a `nym_secrets` from another holder from using that `nym_secrets` with a *signer*, the `nym_secrets` is computed from two distinct parts: *nym_secrets[i]* = *prover_nyms[i]* for i = 1 to N-1 and, *nym_secrets[i]* = *prover_nym[i]* + *signer_nym_entropy* for i = N where N is the length of the *prover_nyms*.

The *prover_nyms* is a a vector of prover secret scalars and is only sent to the *signer* in a binding and hiding commitment. The *signer_nym_entropy* is "blindly added" in by the *signer* during the signing procedure of (#blind-issuance) and sent back to the *prover* along with the signature.

## Pseudonyms

The *pseudonym* is a cryptographic value computed by the prover based on the `nym_secrets` and the `context_id`. At a high level this is computed by from a function of the `context_id` and the `nym_secrets` value. See Section (#pseudonym-calculation-procedure) for details. The pseudonym is sent to a verifier along with the BBS proof.

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

The following pseudo code describes how the pseudonym is calculated from the `nym_secrets` held by the Prover and the public context identifier. The pseudonym will be unique for different contexts (e.g., unique Verifier identifiers) and constant under constant inputs (i.e., the same `context_id` and `nym_secrets`). The `context_id` is an octet string representing the unique identifier of the context in which the pseudonym will have the same value. The `nym_secrets` value is a vector of scalars calculated from secret input provided by the Prover and random (but not secret) input provided by the Signer. This will guarantee uniqueness of the `nym_secrets` between different signatures and users.

```
OP = hash_to_curve_g1(context_id) // a point in the curve group G1
z = hash_to_scalar(context_id)
poly = sum i = 0 to N-1 of nym_secrets[i]*z^i // in the scalar field
pseudonym = OP*poly // in the curve group G1
```

Additionally, the `nym_secrets` value will be signed by the BBS Signature. This will bind the pseudonym to a specific signature, held by the Prover. During proof generation, along the normal BBS proof, the Prover will generate a proof of correctness of the pseudonym, i.e., that it has the form described above, and that it was constructed from the `nym_secrets` signed by the BBS signature used to generate that proof.

# High Level Procedures and Information Flows

To prevent forgeries in all cases all BBS messages are signed with the inclusion of some form of the provider pseudonym secret (`nym_secret`). In addition the pseudonym is always computed by the prover and sent with the proof to the verifier. While two different variations of signature and proof generation are given below based on the previously discussed unlinkability requirements there MUST be only one verification algorithm for the verifier to use.

1. The Prover computes their input for the `nym_secrets` (called `prover_nyms`) and retained for use when calculating the `nym_secrets` value.
2. The Prover will wrap up in a cryptographic commitment using the *CommitWithNym* procedures of Blind BBS the messages they want to include in the signature (`committed_messages`) and the `prover_nyms` value, generating a `commitment_with_proof` and a `secret_prover_blind`.
3. The `commitment_with_proof` is conveyed to the signer which then uses the signing procedures in Section (#signature-generation-and-verification-with-pseudonym) to create a BBS signature and their input for the `nym_secrets` value, called `signer_nym_entropy`. They will convey both to the Prover.
4. On receipt of the signature and the `signer_nym_entropy` value, the Prover verifies the signature using the procedure of section (#signature-generation-and-verification-with-pseudonym) and calculates the `nym_secrets` value by adding their `prover_nyms` secret and the provided `signer_nym_entropy` values as detailed in later sections.
5. The Prover computes the *pseudonym* based on the `nym_secrets` and the pseudonym's context identifier `context_id`.
6. The Prover generates a proof using `nym_secrets`, `secret_prover_blind`, `signature`, `messages`, `committed_messages` and the indexes of the messages to be reveled from those two lists (i.e., `disclosed_indexes` and `disclosed_committed_indexes`)  using the procedures of Section (#proof-generation-with-pseudonym).
7. The Prover conveys the `proof` and `pseudonym` to the verifier. The verifier uses the procedure of Section (#proof-verification-with-pseudonym) to verify the proof.

# BBS Pseudonym Interface

The following section defines a BBS Interface that will make use of per-origin pseudonyms where the `nym_secrets` value is only known to the prover. The identifier of the Interface, api_id,  is defined as `ciphersuite_id || H2G_HM2S_PSEUDONYM_`, where `ciphersuite_id` the unique identifier of the BBS ciphersuite used, as is defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]).

The prover create a `prover_nyms` value and keeps it secret. Only sending a commitment with the proof of the `prover_nyms` that the signer will used when creating the signature.

## Signature Generation and Verification with Pseudonym

### Commitment

This section will describe the steps with which the Signer will generate a blind signature over an array of messages provided (and committed) by the Prover (`committed_messages`) and a pseudonym secret `prover_nym`, also chosen by the Prover. During signature generation, the Signer will provide their own randomness into the pseudonym secret. This will ensure that the pseudonym secret will always be unique, among different signature generation events.

This section will provide a high level description of the required operations, by detailing the modifications required in the relevant BBS blind signature operations, to also consider the use of pseudonyms. The full formal description of the operation can be seen at Appendix. We will reference those operations where appropriate in this section.

Initially, the Prover will chose a set of messages `committed_messages` that they want to be included in the signature, without reveling them to the Signer. They will also choose their part of the pseudonym secret `prover_nym` as a random scalar value.

```
(commitment_with_proof, secret_prover_blind) = CommitWithNym(
                                                   committed_messages,
                                                   prover_nyms,
                                                   api_id)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array ("()").
- prover_nyms (REQUIRED), a vector of random scalar values.
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
2. committed_message_scalars.concat(prover_nyms)

3. blind_generators = BBS.create_generators(
                                  length(committed_message_scalars) + 1,
                                  "BLIND_" || api_id)

4. return Blind.CoreCommit(committed_message_scalars,
                             blind_generators, api_id)
```

### Blind Issuance

The Signer generate a signature from a secret key (SK), the commitment with proof, the length_nym_vector, the signer_nym_entropy and optionally over a `header` and vector of `messages` using
the BlindSignWithNym procedure shown below. The length of the nym vector parameter MUST be furnished by the prover along with the commitment with proof. See the security considerations section for the need for this parameter.

Typically the signer_nym_entropy will be a fresh random scalar, however in the case of
"reissue" of a signature for a prover who wants to keep their same pseudonymous identity this value can be reused for the same prover if desired.

```
BlindSignWithNym(SK, PK, commitment_with_proof, length_nym_vector,
                 signer_nym_entropy, header, messages)

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
- lengh_nym_vector (REQUIRED), the length of the prover_nyms secret vector.
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
9.  combined_header = concat(header, i2osp(length_nym_vector, 8))
10.  blind_sig = Blind.FinalizeBlindSign(SK,
                                  PK,
                                  B,
                                  generators,
                                  blind_generators,
                                  combined_header,
                                  api_id)

11. if blind_sig is INVALID, return INVALID
12. return blind_sig
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
2. B = B + nym_generator * signer_nym_entropy
3. If B is Identity_G1, return INVALID
4. return B
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
                      prover_nyms,
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
- prover_nyms (REQUIRED), a vector of scalar values.
- signer_nym_entropy (OPTIONAL), a scalar value. If not supplied, it
                                 defaults to the zero scalar (0).
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".

Outputs:

- nym_secrets, a vector of scalar values; or INVALID.

Procedure:

1. N = length(prover_nyms)
2. (message_scalars, generators) = Blind.prepare_parameters(
                                            messages,
                                            committed_messages,
                                            length(messages) + 1,
                                            length(committed_messages) + N + 1,
                                            secret_prover_blind,
                                            api_id)

3. nym_secrets = prover_nym.copy()
4. nym_secrets[N-1] = prover_nyms[N-1] + signer_nym_entropy // in scalar field
5. message_scalars.concat(nym_secrets)
6. combined_header = concat(header, i2osp(N, 8));
7. res = BBS.CoreVerify(PK, signature, generators, combined_header,
                                                message_scalars, api_id)

8. if res is INVALID, return INVALID
9. return nym_secrets
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

# Privacy Considerations

# Security Considerations

## Preventing Sybil Attacks

Assuming an honest issuer, to prevent sybil attacks by a malicious prover, we require that the prover use the same set of nym_secrets in computing pseudonyms. In particular, the prover declares the length of the prover_nyms/nym_secrets vectors, N, in their commitment with proof and this value gets bound to the signature from the issuer. In verifying the proof of the pseudonym the verifier will be checking that the N values of the nym_secrets vector was actually used in the computation.

TODO Security

# Ciphersuites

This document does not define new BBS ciphersuites. Its ciphersuite defined in [Section 6](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-ciphersuites) of [@!I-D.irtf-cfrg-bbs-signatures]) can be used to instantiate the operations of the described scheme.

# Test Vectors

## BLS12-381-SHA-256

### Generators

```
api_id = {{ $generatorFixtures.bls12-381-sha-256.generators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-sha-256.generators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-sha-256.generators.Q1 }}

Generators = {

H_0 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[0] }}
H_1 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[1] }}
H_2 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[2] }}
H_3 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[3] }}
H_4 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[4] }}
H_5 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[5] }}
H_6 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[6] }}
H_7 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[7] }}
H_8 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[8] }}
H_9 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[9] }}

}
```

### Blind Generators

```
api_id = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.Q1 }}

Blind Generators = {

J_0 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[0] }}
J_1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[1] }}
J_2 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[2] }}
J_3 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[3] }}
J_4 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[4] }}
J_5 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[5] }}

}
```

### Commit

Mocked random scalar parameters

```
seed = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.mockRngParameters.SEED }}
dst = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.mockRngParameters.commit.DST }}
```

#### valid no committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.committedMessages }}
proverNym = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.proverNym }}
proverBlind = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit001.commitmentWithProof }}
```

#### valid multiple committed messages commitment with proof


```
committedMessages = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.committedMessages }}
proverNym = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.proverNym }}
proverBlind = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.proverBlind }}


Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-sha-256.nymCommit002.commitmentWithProof }}
```

### Signature

#### valid no prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.nymSignature001.signature }}
```

#### valid multi prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.nymSignature002.signature }}
```

#### valid no prover committed messages, multiple signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.nymSignature003.signature }}
```

#### valid multiple signer and prover committed messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.header }}

messages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.nymSignature004.signature }}
```

### Proof

Mocked random scalar parameters

```
seed = {{ $proofFixtures.bls12-381-sha-256.nymProof001.mockRngParameters.SEED }}
dst = {{ $proofFixtures.bls12-381-sha-256.nymProof001.mockRngParameters.proof.DST }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof001.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof001.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof001.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof001.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof001.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof001.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof001.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof001.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof001.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof002.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof002.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof002.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof002.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof002.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof002.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof002.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof002.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof002.proof }}
```

#### valid all prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof003.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof003.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof003.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof003.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof003.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedMessages[8] }}

revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof003.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof003.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof003.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof003.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof004.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof004.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof004.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof004.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof004.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof004.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof004.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof004.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof004.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof005.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof005.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof005.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof005.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof005.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof005.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof005.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof005.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.nymProof005.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.nymProof005.revealedMessages[8] }}

revealedCommittedMessages  = {}


Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof005.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof005.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof005.proof }}
```

#### valid half prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof006.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof006.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof006.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof006.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof006.pseudonym }}

revealedMessages = {}

revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.nymProof006.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.nymProof006.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.nymProof006.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof006.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof006.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof006.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.nymProof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.nymProof007.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.nymProof007.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.nymProof007.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.nymProof007.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-sha-256.nymProof007.pseudonym }}

revealedMessages = {}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.nymProof007.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.nymProof007.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.nymProof007.proof }}
```


## BLS12-381-SHAKE-256

### Generators

```
api_id = {{ $generatorFixtures.bls12-381-shake-256.generators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-shake-256.generators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-shake-256.generators.Q1 }}

Generators = {

H_0 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[0] }}
H_1 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[1] }}
H_2 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[2] }}
H_3 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[3] }}
H_4 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[4] }}
H_5 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[5] }}
H_6 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[6] }}
H_7 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[7] }}
H_8 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[8] }}
H_9 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[9] }}

}
```

### Blind Generators

```
api_id = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.Q1 }}

Blind Generators = {

J_0 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[0] }}
J_1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[1] }}
J_2 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[2] }}
J_3 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[3] }}
J_4 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[4] }}
J_5 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[5] }}

}
```

### Commit

Mocked random scalar parameters

```
seed = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.mockRngParameters.SEED }}
dst = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.mockRngParameters.commit.DST }}
```

#### valid no committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.committedMessages }}
proverNym = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.proverNym }}
proverBlind = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit001.commitmentWithProof }}
```

#### valid multiple committed messages commitment with proof


```
committedMessages = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.committedMessages }}
proverNym = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.proverNym }}
proverBlind = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.proverBlind }}


Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-shake-256.nymCommit002.commitmentWithProof }}
```

### Signature

#### valid no prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.nymSignature001.signature }}
```

#### valid multi prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.nymSignature002.signature }}
```

#### valid no prover committed messages, multiple signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.nymSignature003.signature }}
```

#### valid multiple signer and prover committed messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.header }}

messages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.messages }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.committedMessages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.commitmentWithProof }}

signer_nym_entropy = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.signer_nym_entropy }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.proverBlind }}
proverNym = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.proverNym }}
nym_secret = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.nym_secret }}

Trace:

B = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.nymSignature004.signature }}
```

### Proof

Mocked random scalar parameters

```
seed = {{ $proofFixtures.bls12-381-shake-256.nymProof001.mockRngParameters.SEED }}
dst = {{ $proofFixtures.bls12-381-shake-256.nymProof001.mockRngParameters.proof.DST }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof001.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof001.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof001.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof001.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof001.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof001.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof001.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof001.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof001.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof002.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof002.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof002.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof002.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof002.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof002.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof002.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof002.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof002.proof }}
```

#### valid all prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof003.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof003.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof003.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof003.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof003.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedMessages[8] }}

revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof003.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof003.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof003.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof003.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof004.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof004.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof004.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof004.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof004.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof004.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof004.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof004.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof004.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof005.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof005.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof005.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof005.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof005.pseudonym }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof005.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof005.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof005.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.nymProof005.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.nymProof005.revealedMessages[8] }}

revealedCommittedMessages  = {}


Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof005.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof005.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof005.proof }}
```

#### valid half prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof006.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof006.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof006.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof006.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof006.pseudonym }}

revealedMessages = {}

revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.nymProof006.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.nymProof006.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.nymProof006.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof006.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof006.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof006.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.nymProof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.nymProof007.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.nymProof007.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.nymProof007.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.nymProof007.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.presentationHeader }}

signer_nym_entropy =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.signer_nym_entropy }}
proverNym =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.proverNym }}
nym_secret =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.nym_secret }}
proverBlind =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.proverBlind }}

context_id =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.context_id }}
pseudonym =  {{ $proofFixtures.bls12-381-shake-256.nymProof007.pseudonym }}

revealedMessages = {}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.nymProof007.trace.challenge }}


L = {{ $proofFixtures.bls12-381-shake-256.nymProof007.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.nymProof007.proof }}
```

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

<reference anchor="Chaum85" target="https://dl.acm.org/doi/pdf/10.1145/4372.4373">
 <front>
   <title>Security without identification: transaction systems to make big brother obsolete</title>
   <author initials="D." surname="Chaum" fullname="David Chaum">
    </author>
    <date year="1985"/>
 </front>
 <seriesInfo name="In" value="Commun. ACM"/>
 <seriesInfo name="vol" value="10" />
 <seriesInfo name="pages" value="1030-1044"/>
</reference>

<reference anchor="Lys00" target="https://link.springer.com/chapter/10.1007/3-540-46513-8_14">
 <front>
   <title>Pseudonym Systems</title>
   <author initials="A." surname="Lysyanskaya" fullname="Anna Lysyanskaya">
    </author>
    <author initials="R. L." surname="Rivest" fullname="Ronald L. Rivest">
    </author>
    <author initials="A." surname="Sahai" fullname="Amit Sahai">
    </author>
    <author initials="S." surname="Wolf" fullname="Stefan Wolf">
    </author>
    <date year="2000"/>
 </front>
 <seriesInfo name="In" value="Selected Areas in Cryptography"/>
 <seriesInfo name="vol" value="1758" />
 <seriesInfo name="pages" value="184-199"/>
</reference>

<reference anchor="ABC14" target="https://abc4trust.eu/download/Deliverable_D2.2.pdf.">
 <front>
   <title>D2.2 - Architecture for Attribute-based Credential Technologies - Final Version,</title>
   <author initials="P." surname="Bichsel" fullname="P. Pichsel">
    </author>
    <author initials="et al">
    </author>
     <date year="2014"/>
 </front>
</reference>
