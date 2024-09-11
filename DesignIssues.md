
# Issues and Options for Pseudonyms

How best to implement the two flavors of pseudonyms? (a) issuer/signer known PID, (b) hidden PID only known to holder/prover

## Current and Possible Requirements

* Both types of pseudonyms must use the same proof verification procedure. This was my (Greg B) original requirement when I added hidden PID pseudonym.
* Permit pseudonym feature to be combined with "anonymous holder binding" feature  or multiple holder/prover secret  messages. *Regardless* of  pseudonym type.
* In the ABC4Trust requirements they have an **inspector** role that can de-anonymize the pseudonym by having the PID revealed. This could be the **issuer** but does not have to be. Hence it seems more general to always have a hidden pid and a procedure to reveal the hidden pid for a given credential.
* In the hidden PID case we want to guard against duplication of PIDs or use of stolen PIDs. One way is to have the issuer check on this via secure a secure artifact. One way would be the holder creating an issuer-pseudonym, i.e., pseudo_issuer = H(issuer_public_id)*(holders_PID); And have the issuer check keep a table of these. Note this would have holder send (commitment, pseudo_issuer, proof of commitment and pseudonym)

## Current Approach

The current approach is available  [here](https://www.grotto-networking.com/files/draft-vasilis-bbs-per-verifier-linkability.html) and as a PR on Vasilis' repo.

This approach is characterized by:

1. Use of blind BBS signatures even in the case of issuer known PID
2. Current blind BBS signature API will alway create at least one blind generator even if  there are no committed messages.
3. Blind BBS domain calculation in [CoreBlindSign](https://www.ietf.org/archive/id/draft-kalos-bbs-blind-signatures-01.html#name-core-blind-sign) uses BBS domain calculation over combined list of generators (signer generators, blind generators)
4. Issuer known PID proof message ordering: (issuer messages, issuer known PID), note that a zero for secret_prover_blind + signer_blind is **not** included. So we have a mismatch between number of messages and generators and we must remove the redundant check in step 8 of [BBS.ProofInit()](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-06.html#name-proof-initialization), i.e., `if length(generators) != L + 1, return INVALID`.
5. Hidden PID proof message ordering:  (issuer messages, secret_prover_blind + signer_blind, pid)
6. Pseudonym  proof  verify function  [CoreProofVerifyWithPseudonym](https://www.grotto-networking.com/files/draft-vasilis-bbs-per-verifier-linkability.html#name-core-proof-verification) relies on the *PID value being the last proof message* so it can recover the `pid^` value needed in the pseudonym proof as seen in step 4.

### Issues with Current Approach

1. Some would argue that my approach in step 4 above is a "hack", since we break the correspondence between messages and generators. Though in this case the message is zero.
2. With the above approach we can't combine issuer known PID feature with anonymous holder binding (or other holder secrets) since this would produce message ordering such as (issuer messages, issuer pid, secret_prover_blind + signer_blind, holder committed  messages). Note that in the hidden PID case we can order as (issuer messages, secret_prover_blind + signer_blind, holder committed msgs, holder pid). This is under the one proof verification method assumption.

## Suggested Alternative  Approach

Always use a committed PID with blind signing. In this approach the holder either receives the PID from the issuer or simply reveals the PID they have chosen to the issuer.  They then can add in as many committed secrets as they like, e.g., anonymous holder binding.

Implementation suggestions/additions/details:

1. Always have anonymous holder binding value (if used) be the first committed message and always have the (per credential) PID value be the last.
2. Always compute an "issuer pseudonym" value, pseudo_issuer = H(issuer_public_id)*(holders_PID), to allow the issuer to guard against duplicate PIDs from different holders. Holders would send (PID commitment, pseudo_issuer, proof of commitment and pseudonym)
3. Explicit PID reveal procedure. If issuer or 3rd party tracking is required. Provide a separate proof procedure that generates a proof that reveals just the PID value (and that the PID corresponds to the pseudonym). Recall the holder can reveal any of the blind signed messages of which the PID is the last.

Pros:

1. Unifies both flavors of PID completely.  Only difference is what is revealed to issuer.
2. Issuer known PID can now work with anonymous holder binding and other committed messages. Can have an entity different from issuer do the tracking.
3. Only one pseudonym verification function required
4. Only one pseudonym proof function required

Cons:

1. Extra communication flow in issuer known PID case (holder to issuer). See *mitigation* below.
2. Extra commitment computation for holder in issuer known PID case compared to previous approach. *Minor*
3. Additional proof is needed that revealed PID (issuer known) is in the commitment in the proper place.

### Simple Issuer Known PID (mitigation)

In the case of issuer known PID **without** the holder having additional committed messages to sign the issuer can just generate the PID, commitment, and commitment with proof, and use these in the blind BBS sign procedure.  In order for the holder to  generate the psuedonym proof they only need the  PID and `secret_prover_blind` values  from the issuer.  Note since "blinding" the commitment isn't really necessary (the issuer  knows the PID) we should be able to set `secret_prover_blind` = 0.  Hence the information flow can remain as simple as existing approach.

## Alternative  Approach 2

Drop the requirement for only one pseudonym proof verify procedure or equivalently send an  indicator of which of the two cases are being proved to the verifier.  Just put pid at end of either issuer messages or hidden (committed) messages. Use Blind signatures to allow for committed messages and features like anonymous holder binding. In issuer known PID case the last issuer message is the PID and  `pid^` can be found  via the **L** value used in blind BBS  proofs.  In the hidden PID case the PID is the last committed message.

Pros:

1. Keeps information flow in issuer known PID case simple
2. Allows for issuer  known  PID to work with anonymous holder binding. This is a more complicated information flow and would be equivalent to flow in Approach 1 for this case.

Cons:

1. Requires two different proof verify procedures or extra info to be communicated and a branch in proof verify, i.e., additional primitives for devs to implement and maintain, when the other approach solves the use case without needing them.
