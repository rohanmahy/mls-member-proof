---
title: A membership proof extensions for the Messaging Layer Security (MLS) Protocol
abbrev: MLS membership proof
category: info
ipr: trust200902
docname: draft-mahy-mls-member-proof-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
consensus: true
v: 3
# area: sec
# workgroup: MLS Working Group
keyword:
 - membership proof
 - safe extension
venue:
#  group: MLS
#  type: Working Group
#  mail: mls@ietf.org
#  arch: https://mailarchive.ietf.org/arch/browse/mls/
  github: "rohanmahy/mls-member-proof"
  latest: "https://rohanmahy.github.io/mls-member-proof/draft-mahy-member-proof.html"

author:
 -  ins: R. Mahy
    name: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:


--- abstract

This document describes an MLS safe extension that members of a group
can use to assert membership to non-members.

--- middle

# Introduction

The Messaging Layer Security (MLS) Protocol {{!RFC9420}} is a group key
management protocol which also provides group agreement on the membership
and group context during each epoch. This document defines a Safe Extension
(Section 2 of {{!I-D.ietf-mls-extensions}}) that can be used for members to
assert membership in the group to non-members (for example, an MLS
Distribution Service), such that a dishonest assertion will be immediately
apparent to other members.

This extension includes a new epoch-derived secret called the `member_proof`;
a description of how to export the `member_proof` public key; a
description of how to include in the Additional Authentication Data (AAD)
of MLS encrypted messages, and a signature of a usage-specfic struct of an
encrypted message signed with the `member_proof` private key.

Depending on the specific usage of this extension, signing specific MLS
messages could be either required for every member of a group, or used
optionally by any member as it sees fit.

The document also defines a usage for sharing signatures of handshake messages so they can be safely shared out-of-band with another party
(for example an MLS Distribution Service).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document refers to TLS Presentation Language {{!RFC8446}} structs
defined in the MLS protocol {{!RFC9420}}.

# Mechanism

## Sending a PrivateMessage with a membership proof

This document defines a new Safe Extension for sending a membership
proof in the Additional Authenticated Data (AAD) of an MLS PrivateMessage.
A sender follows the following steps:

1. Derive the `member_proof` key pair using the ExtensionType
`member_proof`. The private key is known as `MemberProofPrivKey`
and the public key is known as `MemberProofPubKey`.

2. Generate a new unique nonce of `KDF.Nh` octets using the Key
Derivation Function of the current cipher suite.

3. Calculate the hash of the concatenation of the nonce and whatever
data (the `UsageData`) is required by the usage of the application.
The hash function is the hash function from the current cipher suite.
The hash is known as the (`ContentHash`)

~~~
ContentHash = hash(concatenation(nonce + FramedContent))
~~~

4. Sign `ContentHash` with the `ExtensionType` for the usage,
using the `member_proof` private key (`MemberProofPrivKey`):

~~~
safe_signature = SafeSignaSafeSignWithLabel(
   ExtensionType, MemberProofPrivKey, Label, ContentHash)
~~~

where `ExtensionType` is the IANA-assigned value for
the usage, `MemberProofPrivKey` is the private
key derived from `member_proof` for the current epoch, and
`ContentHash` is calculated in the previous step.
(Label is defined as "MLS 1.0 ExtensionData" in
{{!I-D.ietf-mls-extensions}}.)

5. The `MemberProofAAD` struct is conveyed in the `aad_item_data` of the
`aad_items` of the `authenticated_data` of the `PrivateMessage`, using
the usage's `ExtensionType`.

``` tls
struct {
   opaque nonce<V>;
   opaque safe_signature<V>;
   optional opaque MemberProofPubKey;
} MemberProofAAD;
```

The `MemberProofPubKey` public key SHOULD be included unless the
sender knows the intended target will receive it another way.

## Verifying a PrivateMessage with a membership proof

1. Verify that the AAD in messages conforms to the policy of the group
(that required items are present, and forbidden )

2. If present, find the MemberProofAAD in the `aad_items` of the
`authenticated_data` of a PrivateMessage; extract the nonce,
`safe_signature` and `MemberProofPubKey`.

3. Members verify that the `MemberProofPubKey` matches the derived
key for `member_proof` for the current epoch.

4. Members calculate the `ContentHash` of the nonce and the relevant
`UsageData`.

5. Members verify that the `safe_signature` is correct.

6. Perform any additional usage-related verifications.

# Handshake Sharing Usage

This document also defines a usage of this member proofs to share an
unencrypted copy of the `FramedContent` of commits and proposals
(collectively handshake messages) that are inside an MLS `PrivateMessage`,
typically to an MLS Distribution Service (DS). It creates the
`handshake_framed_data_hash` `extension_type`. For this usage the
`UsageData` consists of the `FramedContent` of the handshake message.

The client sending the handshake message makes an assurance that the
handshake message is the same as the encrypted one.

The sharing client can share a copy of the FramedContent of the
handshakes with the DS. The DS calculates the signature on FramedContent
it receives with the signature in the MemberProofAAD of the PrivateMessage.
Other members compare the signature in the MemberProofAAD with their own
in-group copy of the FramedContent. If the signature does not match, the
other members know that the the sharing client is either malicious or
has a bug. In either case, the other clients know that they can no longer
trust the sharing client and can take whatever actions are necessary to
exclude it (ex: informing the DS, forcibly removing the client from the
group if possible, or creating new groups without the client).

When a client sends commit message using this usage, it can also send a
`SafeAADItem` with the `extension_type` of `next_epoch_member_proof_key`.
The `aad_item_data` is the public key of the `member_proof` for the next
epoch, if the commit is accepted by the group.

Other members which receive a `next_epoch_member_proof_key` extension
in the `aad_items` of the `authenticated_data` need to verify that it
was sent only in a commit, and that the public key would be correct if
the commit is accepted. (If the commit is already invalid for other
reasons, the client does not need to continue this verification).

# New Requirements on Safe Extensions framework

This document depends on two new features of the Safe Extensions
framework, currently documented in PRs #28 (exporting the `member_proof`
public key) and #29 (framing/muxing of AAD) on
{{!I-D.ietf-mls-extensions}}.

# Security Considerations

TODO

# IANA Considerations

This document requests the addition of various new values under the heading
of "Messaging Layer Security".  Each registration is organized under the
relevant registry Type.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Extension Type handshake_framed_data_hash

* Value: To be assigned by IANA
* Name: handshake_framed_data_hash
* Message(s): AD: This extension may appear in SafeAADInfo objects.
* Recommended: Y
* Reference: RFC XXXX

## MLS Extension Type next_epoch_member_proof_key

* Value: To be assigned by IANA
* Name: next_epoch_member_proof_key
* Message(s): GC, AD: This extension may appear in GroupContext objects
              and/or SafeAADInfo objects.
* Recommended: Y
* Reference: RFC XXXX


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
