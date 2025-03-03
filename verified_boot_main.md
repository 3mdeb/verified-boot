# Verified Boot

## 1. Introduction

The purpose of this section is to define the fundamental concepts and key
terminology that will be utilized throughout the document.
A clear understanding of them is essential for ensuring consistency and
precision.

### Trust, chain of trust, root of trust

#### Trust

> A characteristic of an entity that indicates its ability to perform certain
functions or services correctly, fairly and impartially, along with assurance
that the entity and its identifier are genuine.

~ NIST SP 800-152, Appendix B, Glossary [^NIST_sp800-152]:

> The confidence one element has in another that the second element will behave
as expected.

~ NISTIR 8320, section 1.2 Terminology, under "Trust" [^NIST_ir8320]

#### Root of Trust (RoT)

The **Root of Trust (RoT)**  is a hardware, firmware, or software component, that is
trusted inherently, implicitly and undeniably. The trust towards the
**Root of Trust** cannot be proven. Otherwise the software, hardware, or person
proving, that the **Root of Trust** can be relied on, would be the actual
**Root of Trust**. The security of the whole system
depends on the **Root of Trust** and compromising it makes all the subsequent
security measures ineffective. The main purpose of the **Root of Trust** is to
verify if the next hardware, firmware, or software component to which control
is to be passed can be trusted.[^NIST_ir8320_glossary] [^NIST_sp800-172_A] [^NIST_sp800-193_glossary] [^NIST_sp800-155_glossary]

#### Chain of Trust (CoT)

A **Chain of Trust (CoT)** is a sequence of hardware, firmware, or software
components, where every component in the sequence is verified to be trusted by
the previous component in the chain. The only exception is the **Root of Trust**
, which is the first link in the chain, and the first component that is able
to verify the trust to some other component. A **Chain of Trust** is not
a physical construct kept in memory, but a history of trust transitioning during
the lifetime of a computer system. Once a trusted component passes control to
one that is not verified to be trusted, the **Chain of Trust** ends.
[^NIST_sp800-193_glossary] [^NIST_ir8320_glossary]

#### Trusted Computing Base (TCB)

> Totality of protection mechanisms within a computer
system, including hardware, firmware, and software, the
combination responsible for enforcing a security policy.

~ CNSSI 4009, Commitee on National Security Systems (CNSS) Glossary [^CNSSI_4009]

The meaning of the Trusted Computing Base is different from a Chain of Trust,
in that a Chain of Trust means a sequence of components, that transition their
trust onto each other without necesarilly specifying the role of the components.
The Trusted Computing Base, on the other hand, refers to all of the hardware,
firmware and software components that play a crucial role in the system's
security, without specifying any relations between them.

The components belonging to the Trusted Computing Group include a number of the
initial elements of all the Chains of Trust in a system, and the Roots of Trust
in particular - the elements which form the "Base" for providing security
functionalities.

A bug or a vulnerability of a part of the Trusted Computing Base impacts the
security of the system, while a flaw of a component from outside the TCB
does not. Because of that the size and complexity of the TCB should be minimal
to reduce the risk of undetected vulnerabilities and make it easier to perform
security audits.

### Categorization of chains/roots of trust

Multiple **Chains** and **Roots** of trust can be distinguished based on the
used mechanisms and type of integrity assurances provided by them.

The list and the definitions are not strict and some documents and
implementations may call and group the trusted components in different ways.
The most frequently recognized **Chains** and **Roots** of trust are described
in this section. [^NIST_ir8320_a2]

#### RTM (Root of Trust for Measurements)

The **Root of Trust for Measurements (RTM)** is the first hardware, firmware, or
software component able to measure the integrity of other components, and to
document the history of the measurements.[^TCG_glossary] [^NIST_sp800-155_glossary]
It is the **Root of Trust** for the **Chain of Trust** of all the components
performing integrity measurements.
The history of measurements and the digests of the measured components
need to be saved in a tamper-resistant log, the integrity and authenticity of
which can be verified.

The **Root of Trust for Measurements** is the most important component for
performing the process of **measured boot**.

The **Root of Trust for Measurements** is the most important component for
performing the process of **measured boot**. Depending on the time of
initialization, we can differentiate:
- Static Root of Trust for Measurements (S-RTM)
- Dynamic Root of Trust for Measurements (D-RTM)

##### S-RTM (Static Root of Trust for Measurements)

> An RTM where the initial integrity measurement occurs at platform reset.
The S-RTM is static because the PCRs associated with it cannot be re-ini-
tialized without a platform reset.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

##### D-RTM (Dynamic Root of Trust for Measurements)

> A platform-dependent function that initializes the state of the platform and
provides a new instance of a root of trust for measurement without rebooting
the platform. The initial state establishes a minimal Trusted Computing
Base.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> The D-RTM, if supported by the platform, may start at
any point after boot by initializing the state of the platform without requiring
a reboot. In general, the D-RTM launches after an S-RTM, but the trust-chains
anchored in each RTM are independent.

~ Trusted Computing Group, TCG PC Client Platform Firmware Integrity
Measurement, V1.0, rev 43, 3.1.2 Overview of Roots of Trust

#### RTR (Root of Trust for Reporting)

> The RoT for Reporting (RTR) is a RoT that reliably provides authenticity and
non-repudiation services for the purpose of attesting to the origin and
integrity of platform characteristics. It necessarily leverages the RTM and
RTS. A principal function of the RTR is to provide an unambiguous identity,
statistically unique for the endpoint in the form of an Attestation Key (AK).
The AK may be persistent or temporary. A typical usage of the AK in this
instance involves a TPM2_Quote of the TPM PCRs signed by the AK that may be
accompanied by a certificate.

~ Trusted Computing Group, TCG PC Client Platform Firmware Integrity
Measurement, V1.0, rev 43, 3.1.2 Overview of Roots of Trust

> A computing engine capable of reliably reporting information
provided by the RTM and its measurement agent(s) or held by the RTS.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155_glossary]

<!-- TODO I can't say more for now. Need to read the documents in detail to know
what exactly it is. Some code to verify integrity&authenticity and/or key store?-->

#### RTS (Root of Trust for Storage)

> A computing engine capable of maintaining a tamper-evident
summary of integrity measurement values and the sequence of those measurements.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155]

> TCG defines the RoT for Storage (RTS) as the combination of a
RoT for Confidentiality (RTC) and a RoT for Integrity (RTI). The RTS provides
for confidentiality and integrity of data stored in TPM shielded locations.
In the context of this specification, the RTS maintains a tamper-evident
summary of the integrity measurement values and the sequence of those
measurements. It does not include the details of the sequence of integrity
measurements, but rather holds cumulative integrity results for those sequences.
These cumulative integrity values can either be used to verify the integrity of
a log containing the integrity measurement values and the sequence of those
measurements, or it can be used as a proxy for that log.

~ Trusted Computing Group, TCG PC Client Platform Firmware Integrity
Measurement, V1.0, rev 43, 3.1.2 Overview of Roots of Trust

<!-- TODO I can't say more for now. Need to read the documents in detail
Is it just an encrypted data store?-->

#### RTV (Root of Trust for Verification)

> An RoT that verifies an integrity measurement against a policy

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> The core RoT for verification (CRTV) is responsible for verifying the first
component before control is passed to it.

~ NIST IR 8320, section 3.2 The Chain of Trust (CoT) [^NIST_ir8320]

<!-- TODO I can't say more for now. Need to read the documents in detail
RTC seems to be similar to RTR.
RTR - Integrity+authenticity of data
RTC - Integrity+authenticity of software components-->

### Difference between integrity and authenticity verification

#### Integrity Verification

Integrity:
> A property whereby data has not been altered in an
unauthorized manner since it was created, transmitted, or
stored.

~ NIST SP 800-152, Appendix B Glossary [^NIST_sp800-152]

Data integrity is most of the time assured using hash digests
of the data, which are sent or stored alongside it. Hash digests are often
just called `digests` in the context of data integrity.

Digest:
> The output of a hash function (e.g., hash(data) = digest).
Also known as a message digest, digest or harsh value.

~ NIST IR 8202, Appendix B -- Glossary [^NIST_ir8202]

Hash function:
> A function that maps a bit string of arbitrary length to a fixed-length bit
string. Approved hash functions satisfy the following properties: 1. One-way –
It is computationally infeasible to find any input that maps to any
pre-specified output. 2. Collision resistant – It is computationally
infeasible to find any two distinct inputs that map to the same output.

~ NIST SP 800-175, section 1.5 Terms and Definitions [^NIST_sp800-175]

To verify the integrity of the data, the digest has to be calculated once
more and compared against the one received.
When creating digests using a strong hash function, even the
smallest change to the data will result in a completely different value
of the digest and chaning the data in such a way that won't change the
digest is not feasible computationally.

Only verifying integrity does not guarantee the origin of the data is
genuine. A bad actor could modify both the data and the digest if the digest
is not protected or already known from a different source.

#### Authenticity

> The property of being genuine and being able to be verified and trusted;
confidence in the validity of a transmission, a message, or message originator.

~ NIST SP 800-137, Appendix B Glossary [^NIST_sp800-137]

Verifying authenticity is verifying the identity of an entity.
It is performed using asymetric cryptography. The private key of an asymmetric
cryptography keypair is often called the `identity`. In this context, proving
an identity is proving to be in possession of the private key.

The simplest way an entity can prove it's identity is to encrypt a well known
data using it's private key. If decrypting the data with a public
key yields the same data, then it must have been encrypted using the
corresponding private key.

Verifying authenticity requires one to be in posession of a public key, that
is trusted to correspond to the private key of the to bo authenticated entity.
<!-- TODO? tell about how it is solved? certificate stores in UEFI / PKI? -->

Authenticity itself does not guarantee the integrity of data.

##### Non repudiation

> A service that is used to provide assurance of the integrity and origin of data in such a way that the integrity and origin can be verified and validated by a third party as having originated from a specific entity in possession of the private key (i.e., the signatory).

~ NIST FIPS 186-5 [^NIST_fips186-5]

Non repudiation is a term used to describe a data, of which both the
integrity and the authenticity of some entity responsible for it
can be verified.
Non repudiation is generally achieved using some form of digital
signature.

Digital Signature
>  A cryptographic technique that utilizes asymmetric-keys to determine
authenticity (i.e., users can verify that the message was signed with a private
key corresponding to the specified public key), non-repudiation (a user cannot
deny having sent a message) and integrity (that the message was not altered
during transmission).

~ NIST SP 800-63, Appendix A - Deifinitions and Abbreviations [^NIST_sp800-63]

A basic digital signature is a digest of data, that has been encrypted using the
private key of some entity.
Verifying a signature requires:
- The data in plaintext
- The digital signature of the data
- The public key corresponding to the private key of the signer
- Knowledge of the hash function used to calculate the digest and the type of
assymetric keys used by the signer

<!-- TODO? digest is not necesarry, it just saves some time if the data is large, because asym. crypt. is slow -->

The process consists of:
- calculating the digest using the same hash function as used by the signer
- decrypting the signature using signer's public key to receive the digest in
  plaintext
- comparing the two values

The verification of the signature succeeds if both digests are exactly the same.
If the verification succeeds then:
- Integrity is verified. The received digest is the same as the one
calculated from the datum. The data did not change
<!-- TODO? only if the used hash function is safe? -->
- Authenticity is verified. Only the one in possession of the corresponding
private key could have encrypted the digest so that it can be decrypted using
the public key

### The difference between verified boot and measured boot
<!-- - 457-465    "Measured Boot vs Secure Boot" -->

Verified boot and measured boot are two fundamentally different concepts, which
serve different purposes in a computer system.


#### Verified Boot



<!--
I can't seem to find definitions from NIST or TCG. This section might require
more than giving a couple citations.

verified boot - Verifying the signatures of software components using some trusted public keys
measured boot - extending the digests (in PCRs) with every launched software component.
Does not really protect anything on it's own. The values in PCRs can be compared to some
known and expected values at any point. If they differ then the code executed
up to this point was different than expected and may suggest a threat -->

[^NIST_sp800-63]: NIST SP 800-63, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf
[^NIST_sp800-137]: NIST SP 800-137, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
[^NIST_sp800-147_glossary]: NIST SP 800-147 Appendix B — Glossary, https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf
[^NIST_sp800-152]: NIST SP 800-152, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-152.pdf
[^NIST_sp800-155]: NIST SP 800-155, https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp800-155_glossary]: NIST SP 800-155, section 3.6.4, Appendix B — Glossary and Abbreviations, https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp_800-172_A]: NIST SP 800-172, Appendix A, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-172.pdf
[^NIST_sp800-175]: NIST SP 800-175, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf
[^NIST_sp800-190]: NIST SP 800-175, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
[^NIST_sp800-193_glossary]: NIST SP 800-193, Appendix B — Glossary, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf
[^TCG_glossary]: TCG Glossary, https://trustedcomputinggroup.org/wp-content/uploads/TCG-Glossary-V1.1-Rev-1.0.pdf
[^NIST_ir8202]: NIST IR 8202, https://nvlpubs.nist.gov/nistpubs/ir/2018/NIST.IR.8202.pdf
[^NIST_ir8320_glossary]: NIST IR 8320, Appendix H — Glossary, https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_ir8320_a2]: NIST IR 8320, Appendix A, section 2, Hardware Root of Trust: Intel TXT and Trusted Platform Module (TPM), https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_ir8320_3-2]: NIST IR 8320, section 3.2 - The Chain of Trust (CoT), https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_fips186-5]: NIST FIPS 186-5, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf

## 2. Definition of requirements
- 584-645    "Notes"
- 869-874    "See Also"

### Threat model

### Functional requirements
- 646-684    "Firmware and Device Requirements"; ch. 2"

### Non-functional requirements

## 3. Firmware
- 884-914    "Part 1 - Hardware and Firmware"
- 915-938    "Part 2: Firmware and OS"

### Implementations of verified boot

#### Legacy

#### UEFI

#### Heads

### Firmware protections against changing settings in its UI

### Firmware protections against changing firmware's flash chip
- 811-831    "Write Protection"

### Intel Boot Guard / AMD Platform Secure Boot

## 4. OS-level approaches at limiting system modification
- 836-850    "Other Distributions implementing Verified Boot"
- 851-863    "Immutable Linux Distributions"
- 864-868    "Forum Discussion"
- 915-938    "Part 2: Firmware and OS"

### Role-based boot modes

### Read-only/discardable-file-systems

### Checksum verification

### dm-verity

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
