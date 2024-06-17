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

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Mechanism


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
