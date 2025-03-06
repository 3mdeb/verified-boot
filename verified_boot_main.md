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

~ NISTIR 8320, section 1.2 Terminology, under "Trust" [^NIST_ir8320A_1-2]

It's worth noting that the "element" or "entity" in these definitions might
not only be a software or hardware component, but also a person or an organization
as well. A person using their computer **Trusts** its hardware, software,
firmware, the UEFI Secure Boot certificate issuers, the PKI
Certificate Authorities and more.

#### Root of Trust (RoT)

The **Root of Trust (RoT)**  is a hardware, firmware, or software component, that is
trusted inherently, implicitly and undeniably. The trust towards the
**Root of Trust** cannot be proven. Otherwise the software, hardware, or person
proving, that the **Root of Trust** can be relied on, would be the actual
**Root of Trust**. The security of the whole system
depends on the **Root of Trust** and compromising it makes all the subsequent
security measures ineffective. The main purpose of the **Root of Trust** is to
verify if the next hardware, firmware, or software component to which control
is to be passed can be trusted. [^NIST_ir8320_glossary] [^NIST_sp_800-172_A] [^NIST_sp800-193_glossary] [^NIST_sp800-155_glossary]

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

~ CNSSI 4009, Committee on National Security Systems (CNSS) Glossary [^CNSSI_4009]

The meaning of the Trusted Computing Base is different from a Chain of Trust,
in that a Chain of Trust means a sequence of components, that transition their
trust onto each other without necesarily specifying the role of the components.
The Trusted Computing Base, on the other hand, refers to all the hardware,
firmware and software components that play a crucial role in the system's
security, without specifying any relations between them.

The components belonging to the Trusted Computing Base include a number of the
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
document the history of the measurements. [^TCG_glossary] [^NIST_sp800-155_glossary]
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
The S-RTM is static because the PCRs associated with it cannot be reini
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

> A computing engine capable of reliably reporting information
provided by the RTM and its measurement agent(s) or held by the RTS.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155_glossary]

> The RoT for Reporting (RTR) is a RoT that reliably provides authenticity and
non-repudiation services for the purpose of attesting to the origin and
integrity of platform characteristics. It necessarily leverages the RTM and
RTS. A principal function of the RTR is to provide an unambiguous identity,
statistically unique for the endpoint.

~ Trusted Computing Group, TCG PC Client Platform Firmware Integrity
Measurement, V1.0, rev 43, 3.1.2 Overview of Roots of Trust

The role of the Root of Trust for Reporting is to provide the functionality
to reliably present the data from the Root of Trust for Storage protected
medium. It has to verify the integrity and authenticity of the data and
make sure that the data is only presented to authorized entities. The
reports received from the RTR can be used to decide if a threat was detected
in the process of measured boot.

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

These definitions are exhaustive. The role of the RTS is to
maintain the summary and the history of integrity measurements [^NIST_sp800-155_3222]
while keeping its integrity, confidentiality and protecting it from
modifications other than by performing further measurements.
The measurement history might be a list of digests of measured
components and a cumulative hash of all the measured components, which can be
used to verify if the reported sequence of measurements is valid.

#### RTV (Root of Trust for Verification)

> An RoT that verifies an integrity measurement against a policy

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> A root of trust for verification is an
immutable location, such as a boot ROM, which cryptographically verifies the
first mutable firmware in the system. The verification is done using digital
signatures before the mutable firmware is executed.

~ ARM Base Boot Security Requirements, Issue 1.3, section 4.5 - Secure Boot [^ARM_BBSR_4-5]

The Root of Trust for Verification is responsible for verifying components and
enforcing the security policies depending on the results of the verification.

The verification consists of calculating the digest of a component and
verifying it using a certificate, or comparing it against an expected value.
The process of verification requires for the RTV to include a secure database
of trusted certificate issuers and/or trusted digests, which can be extended
by additional components added later to the Chain of Trust for Verification.
Depending on the result of the verification and the used policies, the RTV
might authorize the component being verified to be executed, or not. This
may result in stopping the process of booting the device.

### The difference between verified boot and measured boot
<!-- - 457-465    "Measured Boot vs Secure Boot" -->

Verified boot and measured boot are two fundamentally different concepts, which
serve different purposes in a computer system and are not mutually exclusive.

#### Verified Boot

Verified boot can be used to ensure that no unverified components are executed
during boot. This is done by verifying the authenticity of the components using
signatures and certificates or by comparing their digests to a list of expected
and trusted values.

To verify if a code should be executed, verified boot depends on the RTM to
calculate digests and the RTV to verify and decide whether they should be
executed or not.

#### Measured Boot

The purpose of measured boot is not to decide whether to execute the firmware or
software components, but to perform the process of BIOS Integrity Measurements,[^NIST_sp800-155]
to document the process, and to allow analyzing it for unexpected events
after the fact.

Measured Boot depends on the RTM to calculate the digests of executed
components and the RTS for storing the measurements and their summary.
The RTR can then be used to inspect what software components were executed
during the boot process and decide whether the sequence is expected or
if a potential security threat happened.

#### Comparison of verified boot and measured boot

|Criterion|verified boot|measured boot|
|--|--|--|
|Short description|Verifies code signatures before passing execution|Documents what code was executed|
|Security benefits|Only verified software will be executed|It can be determined if something unexpected and potentially dangerous was already executed|
|Required RoTs and CoTs|Verification|Measurement, Storage and Reporting|
|Support|Supported on almost every device|To function properly requires CPU functionality not always available on consumer level devices[^intel_txt]|

#### Cross-references

- Measured boot description by coreboot - https://doc.coreboot.org/security/vboot/measured_boot.html
- Short comparison by SLIM bootloader - https://slimbootloader.github.io/security/boot-guard.html
- Measured and verified boot comparison by the TPM.dev community - https://github.com/tpm2dev/tpm.dev.tutorials/blob/master/Boot-with-TPM/README.md#verified-vs-measured-boot
- Overview of verified boot on Android devices - https://source.android.com/docs/security/features/verifiedboot

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
of the digest and chaining the data in such a way that won't change the
digest is not feasible computationally.

Only verifying integrity does not guarantee the origin of the data is
genuine. A bad actor could modify both the data and the digest if the digest
is not protected or already known from a different source.

#### Authenticity

> The property of being genuine and being able to be verified and trusted;
confidence in the validity of a transmission, a message, or message originator.

~ NIST SP 800-137, Appendix B Glossary [^NIST_sp800-137]

Verifying authenticity is verifying the identity of an entity.
It is performed by comparing the digest against a known one, or by using
asymmetric cryptography. The private key of an asymmetric
cryptography keypair is often called the `identity`. In this context, proving
an identity is proving to be in possession of the private key.

The simplest way an entity can prove its identity is to encrypt a well known
data using its private key. If decrypting the data with a public
key yields the same data, then it must have been encrypted using the
corresponding private key.

Verifying authenticity requires one to be in possession of a public key, that
is trusted to correspond to the private key of the to-be authenticated entity.

Authenticity itself does not guarantee the integrity of data.

The authenticity of data can be verified without using asymmetric cryptography
by comparing the digest to a well known one. The well-known digest must be
known in advance and stored in a tamper resistant or tamper evident store.
If only a trusted entity is able to add or alter the well-known digest, then
by verifying the integrity against it, the data can be verified to be
authentic by the trusted entity.

##### Non repudiation

> A service that is used to provide assurance of the integrity and origin of data in such a way that the integrity and origin can be verified and validated by a third party as having originated from a specific entity in possession of the private key (i.e., the signatory).

~ NIST FIPS 186-5 [^NIST_fips186-5]

Non repudiation is a term used to describe a data, of which both the
integrity and the authenticity of some entity responsible for it
can be verified.
Non repudiation is generally achieved using some form of digital
signature.

Digital Signature:

>  A cryptographic technique that utilizes asymmetric-keys to determine
authenticity (i.e., users can verify that the message was signed with a private
key corresponding to the specified public key), non-repudiation (a user cannot
deny having sent a message) and integrity (that the message was not altered
during transmission).

~ NIST SP 800-63, Appendix A - Definitions and Abbreviations [^NIST_sp800-63]

A basic digital signature is a digest of data, that has been encrypted using the
private key of some entity.
Verifying a signature requires:

- The data in plaintext
- The digital signature of the data
- The public key corresponding to the private key of the signer
- Knowledge of the hash function used to calculate the digest and the type of
asymmetric keys used by the signer

The process consists of:

- calculating the digest using the same hash function as used by the signer
- decrypting the signature using signer's public key to receive the digest in
  plaintext
- comparing the two values

The verification of the signature succeeds if both digests are exactly the same.
If the verification succeeds then:

- Integrity is verified. The received digest is the same as the one
calculated from the datum. The data did not change
- Authenticity is verified. Only the one in possession of the corresponding
private key could have encrypted the digest so that it can be decrypted using
the public key

[^NIST_sp800-63]: NIST SP 800-63, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf
[^NIST_sp800-137]: NIST SP 800-137, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf
[^NIST_sp800-147_glossary]: NIST SP 800-147 Appendix B — Glossary, https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf
[^NIST_sp800-152]: NIST SP 800-152, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-152.pdf
[^NIST_sp800-155]: NIST SP 800-155, BIOS Integrity Measurement Guidelines, https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp800-155_3222]: NIST SP 800-155, section 3.2.2.2 BIOS Integrity Measurement Registers, https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp800-155_glossary]: NIST SP 800-155, section 3.6.4, Appendix B — Glossary and Abbreviations, https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp_800-172_A]: NIST SP 800-172, Appendix A, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-172.pdf
[^NIST_sp800-175]: NIST SP 800-175, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf
[^NIST_sp800-190]: NIST SP 800-175, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
[^NIST_sp800-193_glossary]: NIST SP 800-193, Appendix B — Glossary, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf
[^TCG_glossary]: TCG Glossary, https://trustedcomputinggroup.org/wp-content/uploads/TCG-Glossary-V1.1-Rev-1.0.pdf
[^NIST_ir8202]: NIST IR 8202, https://nvlpubs.nist.gov/nistpubs/ir/2018/NIST.IR.8202.pdf
[^NIST_ir8320_glossary]: NIST IR 8320, Appendix H — Glossary, https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_ir8320_a2]: NIST IR 8320, Appendix A, section 2, Hardware Root of Trust: Intel TXT and Trusted Platform Module (TPM), https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_ir8320A_1-2]: NIST IR 8320A, section 1.2 - Terminology, https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8320A.pdf
[^NIST_ir8320_3-2]: NIST IR 8320, section 3.2 - The Chain of Trust (CoT), https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf
[^NIST_fips186-5]: NIST FIPS 186-5, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
[^CNSSI_4009]: Committee on National Security Systems (CNSS) Glossary, https://rmf.org/wp-content/uploads/2017/10/CNSSI-4009.pdf
[^intel_txt]: Intel Trusted Execution Technology Overview, https://www.intel.com/content/www/us/en/developer/articles/tool/intel-trusted-execution-technology.html
[^ARM_BBSR_4-5]: ARM Base Boot Security Requirements, Issue 1.3, https://documentation-service.arm.com/static/65e84577837c4d065f655931

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
