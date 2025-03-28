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

The Trusted Computing Base, just like the Chain of Trust, can consist of
a different number of components at any given point in the process
of booting th system. When analyzing the boot process, the TCB is increasing
in size with every new component appended to the Chains of Trust that is
important for the security, or might impact it in any way.

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
The S-RTM is static because the PCRs associated with it cannot be
reinitialized without a platform reset.

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
The two mechanisms don't compete nor substitute each other, but they can work
in tandem and one can complement the other.

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
|Time of measurement|Before execution|After execution|
|What it allows|Blocking untrusted components|Documenting what was executed|
|Required RoTs and CoTs|Verification|Measurement, Storage and Reporting|
<!-- better name for the "Popularity" criterion?-->

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

### Implementations of verified boot

Booting the system is a multistep process that might include an arbitrary
sequence of components. In order to perform a verified boot of the system,
every firmware and software component ran after the Root of Trust has to be
verified and verify the next component in the chain. Launching a component that
does not implement verified boot and passes execution to unverified code
breaks the chain of trust and poses a security risk.

#### Legacy

Legacy BIOS firmware is highly implementation dependent. It is common
for BIOS firmware to implement a subset of BIOS interrupt calls[^wikipedia_bic]
compatible with the ones used in the first IBM PCs, but it is not required.

Not every BIOS firmware implements verified boot and the implementations are not
guaranteed to have a compatible API or ABI. Some common open-source non-UEFI
BIOSes that work towards verified boot include:
- `coreboot` - implements both verified boot[^coreboot_vboot][^coreboot_cbfs_verification]
  and measured boot[^coreboot_vboot_measured]
- `skiboot` - implements verified boot and exposes the API as the
  Secure and Trusted Boot Library [^skiboot_libstb]
- `seabios` - exposes the `1Ah` BIOS interrupt, an ABI defined by the TCG[^TCG_1ah]
  that allows interacting with TPM and performing verification and measurements
  by the next launched component[^seabios_1ah]
- `Slim Bootloader` - implements both verified and measured boot[^Slim_security]

[^wikipedia_bic]: https://en.wikipedia.org/wiki/BIOS_interrupt_call
[^coreboot_vboot]: https://doc.coreboot.org/security/vboot/index.html
[^coreboot_vboot_measured]: https://doc.coreboot.org/security/vboot/measured_boot.html
[^coreboot_cbfs_verification]: https://github.com/coreboot/coreboot/blob/35933e40be83667bb2d1e1de9e9618cd690c6124/src/lib/Kconfig.cbfs_verification#L11
[^TCG_1ah]: TCG PC Client Specific Implementation Specification for Conventional BIOS, section https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
[^seabios_1ah]: https://mail.coreboot.org/pipermail/seabios/2011-April/001609.html
[^skiboot_libstb]: https://open-power.github.io/skiboot/doc/stb.html
[^Slim_security]: https://slimbootloader.github.io/security/index.html

#### UEFI

The UEFI specification defines the UEFI Secure Boot protocol[^UEFI_SB] as a security
mechanism that can be used as a part of verified boot process. The protocol
allows to verify the authenticity and integrity of UEFI drivers as well as
the operating system before the hand-off.

What makes Secure Boot special is that the process is very well documented
in the UEFI specification. Different UEFI BIOS implementations can differ
in how exactly it is implemented and whether additional functionalities
are provided, but thanks to the common specification, and standard set of UEFI
Services, any UEFI compatible Operating Systems can be easily booted on any
UEFI BIOS implementation.

UEFI Secure Boot causes some controversy[^Wikipedia_uefi_criticism] due to the fact that most hardware
comes with Microsoft keys enrolled, and that most firmware and operating systems
come signed by those keys. The Debian Wiki [^Debian_sb] explains how this fact,
depending on the implementation, does no harm to security nor freedom, as
the keys can be modified.

[^UEFI_SB]: UEFI Specification Version 2.10 Erata A, Section 32 - Secure Boot and Driver Signing, https://uefi.org/specs/UEFI/2.10_A/32_Secure_Boot_and_Driver_Signing.html#secure-boot-and-driver-signing
[^Debian_sb]: Debian Wiki, "What is UEFI Secure Boot?" https://wiki.debian.org/SecureBoot
[^Wikipedia_uefi_criticism]: https://en.wikipedia.org/wiki/UEFI#Secure_Boot_criticism

#### Heads

Heads consists of a custom coreboot[^Heads_coreboot][^coreboot] firmware
and a minimal Linux kernel embedded in the SPI chip[^Heads_intro]. It is
a complete package of firmware components that allows to boot the operating
system securely.

The main point of Heads is to move the authority to verify the trust towards
a computer system from an OEM or a corporation back to the user.

Heads[^Heads_by_trammel_hudson] uses measured boot to measure the integrity of
the whole system. This includes the proprietary binary blobs provided by
the CPU vendors. The measurements are saved inside the TPM module serving
as an RTS for the purpose of verifying if the system's integrity was not
compromised when booting next time.
Additionally Heads implements verified boot by signing
and verifying its components using keys controlled by the user, preferably
in the form of a hardware token[^Heads_by_trammel_hudson_33c3]. The user keys
are not only used to authenticate the user to the system, but also to
authenticate the system to the user.

[^coreboot]: https://coreboot.org/
[^Heads_intro]: https://osresearch.net/#overview
[^Heads_coreboot]: https://osresearch.net/FAQ/#why-replace-uefi-with-coreboot
[^Heads_by_trammel_hudson]: https://trmm.net/Heads/
[^Heads_by_trammel_hudson_33c3]: Heads 33c3, section "Code signing", https://trmm.net/Heads_33c3/

### Firmware protections against changing settings in its UI

Changing the BIOS firmware settings via its UI is the easiest way to affect
the firmware and it's security. It requires next to no technical knowledge
or preparations.

Typically two factors are used to authenticate changes in firmware settings
using the UI:
- Physical presence - Because the UI is presented on a screen and the inputs
are incoming from an external device it is often safe to assume that a person,
not malicious code, is accessing the settings, and so the changes may be treated
as authenticated as done intentionally by a user.
- BIOS Password - In scenarios where a higher security is required most BIOS
firmware implementations[^Dasharo_password][^MSI_password][^system76_password][^Gigabyte_password] provide a way to set up a password which protects the settings
from being changed by an unathorized user.

<!--

https://docs.dasharo.com/dasharo-menu-docs/overview/#user-password-management

http://osresearch.net/FAQ/#why-use-linux-instead-of-vboot2
> by moving the verification into the boot scripts we’re able to have a much
  flexible verification system and use more common tools like PGP to sign firmware stages

 -->

 [^Dasharo_password]: Dasharo menu overwiew, User password management, https://docs.dasharo.com/dasharo-menu-docs/overview/#user-password-management
 [^MSI_password]: MSI DT BIOS Manual, under "Security", https://www.msi.com/support/technical_details/DT_BIOS_Manual
 [^system76_password]: System76 Technical Documentation, Security, https://tech-docs.system76.com/models/addw1/setup-specs.html#security
 [^Gigabyte_password]: Gigabyte BIOS Setup User's Guide, Chapter 1, under "Security", https://download.gigabyte.com/FileList/Manual/server_manual_r121-x30_bios_e_1.0.pdf

### Firmware protections against changing firmware's flash chip

The processes of verified boot and measured boot can be used to detect that
the system's security might have been compromised and react to it accordingly.

Protecting the firmware's flash chip from being modified, on the other hand,
is a precaution that might save the device from being compromised or tampered
with. Making the chip read only should make it impossible to add an untrusted
component to the boot process. Such protections only apply to modifying the
flash chip via the integrated programmer that can be operated by the CPU
and the software running on it. They don't protect the flash chip from being
reprogrammed by physically connecting an external programmer device to it.

On the example of Intel platforms, the supported protections are described
in the chipset Platform Controller Hub datasheets and consist of a couple
mechanisms:

- Flash Descriptor Master Region [^Intel_series_9_pch_5-26-2-1]
  - Defines the structure of firmware regions
  - Controls the read and write access to the regions
  - The *Master* [^Intel_series_9_pch_5-26-2-1] of the region can access it
    no matter the access setting
  - The CPU is the *Master* of the BIOS region, so this mechanism
    is not enough to protect the BIOS from malicious software
- Global Write Protection [^Intel_series_9_pch_5-26-5-1]
  - Blocks the executed code from writing to the SPI flash
  - System Management Mode (SMM) code can turn it on/off anytime
  - Disabling the protection from non-SMM code launches a
    System Management Interrupt that can prevent the protection from being
    disabled
  - SMM BIOS Write Protection [^Intel_series_9_pch_12-1-33]
    - Part of the Global Write Protection mechanism
    - Can prevent non-SMM code from writing to the BIOS chip regardless
      of the other settings
    - Nowadays known as Enable InSMM.STS (EISS) [^Intel_800_series_pch_vol2]
- BIOS Range Write Protection [^Intel_series_9_pch_5-26-5-1]
  - Blocks writes to a specific address ranges of the SPI flash chip memory
  - Can only be turned off by a system reset

<!--
https://eclypsium.com/blog/firmware-security-realizations-part-3-spi-write-protections/
https://opensecuritytraining.info/IntroBIOS_files/Day2_03_Advanced%20x86%20-%20BIOS%20and%20SMM%20Internals%20-%20SPI%20Flash%20Protection%20Mechanisms.pdf
https://nixhacker.com/analyse-bios-protection-against-uefi-rootkit/
https://cdrdv2-public.intel.com/743835/743835-004.pdf, section 27.1.1
 -->

[^Intel_series_9_pch]: https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/9-series-chipset-pch-datasheet.pdf
[^Intel_series_9_pch_5-26-2-1] Intel 9 Series Chipset PCH, section 5.26.2.1: https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/9-series-chipset-pch-datasheet.pdf
[^Intel_series_9_pch_5-26-5-1] Intel 9 Series Chipset PCH, section 5.26.2.1: https://www.intel.com/content/dam/www/public/us/en/documents/datasheets/9-series-chipset-pch-datasheet.pdf
[^Intel_series_800_pch_vol2] Intel 800 Series Chipset PCH, Volume 2, https://edc.intel.com/content/www/us/en/design/publications/800-series-chipset-family-platform-controller-hub-pch-volume-2/bios-control-bios-spi-bc-offset-dc/


### Intel Boot Guard / AMD Platform Secure Boot

The two technologies are mostly equivalent and serve the purpose of providing
Hardware Roots of Trust, which are harder to compromise than software-based
ones, and allowing to create uninterrupted Chains of Trust from the hardware
up to an operating system.

The two implementations include, but are not limited to:
- A secure storage for enrolling keys by the OEM. Possibly using electronic
fuses[^efuses_wikipedia] that make the keys permamently encoded into the CPU
- Hardware implementations of basic cryptography operations
- A small read-only code for verifying the firmware

While similar in essence, Intel Boot Guard and AMD Platform Secure Boot use
different naming for equivalent steps and elements of the technologies.

#### Intel Boot Guard

Intel Boot Guard[^Intel_introduction_to_key_usage] is a technology that
implements the RTM and the RTV in hardware.
The hardware-based RTV works by verifying the initial part of the firmware
called the `Initial Boot Block (IBB)` using the `Authenticated Code Module (ACM)`
code embedded in the CPU by the manufacturer. The IBB is verified using the OEM
keys, that are saved in the CPU registers and can be fused to make them
permamently read-only. The IBB is the second link of the CTV and continues
to extend it by verifying the rest of the BIOS firmware.

[^Intel_introduction_to_key_usage]: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html

#### AMD Platform Secure Boot

The AMD Platform Secure Boot[^AMD_PSB] (formerly known as AMD Hardware
Validated Boot[^AMD_HVB]), provides the Hardware RTV thanks to the
`AMD Secure Processor (ASP)` (formerly known as Platform Security
Processor - PSP), which is logically isolated from the CPU.
The ASP executes the `ASP boot loader code` - a read only code embedded within
the ASP, which verifies an initial part of the firmware called the `Secure Loader (SL)`
using keys fused into the CPU. Verifying the SL makes it the second link of the CTV.
The Secure Loader then extends the
Chain of Trust for Verification by verifying the rest of the BIOS firmware.

[^AMD_HVB]: https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/5th-gen-amd-epyc-processor-architecture-white-paper.pdf
[^AMD_PSB]: https://www.amd.com/content/dam/amd/en/documents/products/processors/ryzen/7000/ryzen-pro-7000-security-whitepaper.pdf
[^efuses_wikipedia]: https://en.wikipedia.org/wiki/EFuse

## 4. OS-level approaches at limiting system modification
- 836-850    "Other Distributions implementing Verified Boot"
- 851-863    "Immutable Linux Distributions"
- 864-868    "Forum Discussion"
- 915-938    "Part 2: Firmware and OS"

### Role-based boot modes

Role-Based boot is a term proposed by Kicksecure, it is a concept of booting
operating system into different modes based on user roles in order to enhance
security. Each role (mode) should have limited variety of workloads it's
allowed to perform and limited access to resources. This is similar to
principle of least privilege. The aim for role-base boot concept is to develop
more secure and flexible OS environments by tailoring boot models to specific
user roles for performing permissible range of tasks.

Role-based boot is implemented in Kicksecure and Whonix operating systems.
Currently supported boot modes are[^1]:
* `PERSISTENT mode USER` - provides persistency for user files. The
user operates with standard permissions, but they're not allowed to escalate
privileges (e.g. by executing `sudo` command). All locations remain writable
including `/tmp` and `/dev/shm`.
* `LIVE mode USER` - serves similar role to `PERSISTENT mode USER` with the
difference that any changes made to the filesystem are not persistent and will
be lost during reboot.
* `PERSISTENT mode SYSMAINT` - Grants access to special system maintenance
account, which can escalate privileges in order to perform administrative
tasks. Provides a full persistence.

Complete implementation details can be found
[here](https://www.kicksecure.com/wiki/Dev/user-sysmaint-split).

Another example that implement multiple boot modes, but are not referred to as
role-base boot, is ChromeOS. ChromeOS includes following boot modes[^2]:
* Normal mode - default boot option, performs full verification of firmware and
OS components.
* Recovery mode - Used for OS and read-writable firmware components repair.
* Developer mode - relaxes some of the restrictions in Verified Boot Mode,
allows root access, modification of system components or upgrading firmware.
* Legacy boot mode - allows for booting alternate OS.

[^1]: [user-sysmaint-split](https://www.kicksecure.com/w/index.php?title=Dev/user-sysmaint-split)
[^2]: [chromeos-boot-modes](https://docs.mrchromebox.tech/docs/boot-modes/)

### Read-only

In this chapter, various meanings of "read-only" concept will be explored.

#### Read-only physical media

A read-only, in context of storage media, refers to the property of some
storage medias like ROM chips, CD-ROMs or DVD-ROMs that hold their content
permanently. In theory, a content can be read, but not updated nor removed[^1].

Below are detailed explanations of listed read-only physical media examples:
* ROM chips - ROM (Read-Only Memory) is a non-volatile memory type used in
various electronic devices to store firmware or software that's hardly changed.
There exist certain types of ROM memory that can be modified despite being
having "read-only" in the name. These extend ROM functionality, examples
are[^2]:
    * PROM - programmable read-only memory. A type of ROM memory that allows
    data to be "written" only once after manufacturing. Word "written" has been
    put in quotes, as writing and programming are considered different
    processes.
    * EPROM and EEPROM - types of Erasable Programmable Read-Only Memory. Both
    memory types can be erased and reprogrammed. For EPROM this is done by
    exposing the chip to ultraviolet light, EEPROM on the other hand can be
    reprogrammed electrically, which makes it suitable for applications where
    data (e.g. firmware) must be updated from time to time. Example is BIOS
    chips.
* Optical media - for optical media, a laser beam is used to read and write
data of the medium. Optical mediums, often come in form of disc. Similar to
ROM, the optical mediums can be split into two categories: read-only optical
discs and recordable optical discs[^3]:
    * read-only optical discs - types of optical discs that have data
    permanently written on them, during manufacturing process. Examples are
    CD-ROM (Compact Disc - Read-Only Memory) and DVD-ROMs (Digital Versatile
    Disc - Read-Only Memory).
    * recordable optical discs - allow for recording data with process named
    "burning". These further split into:
        * recordable medias like CD-R and DVD-R where data can be burnt until
        disc is full, but it cannot be erased.
        * rewritable medias like CD-RW and DVD-RW where data can be burnt and
        erased.

Some of the physical medias can have physical toggle switch that makes them
write-protected or read-only, example being SD cards. It should be noted that
SD cards switch works only as suggestion, and can be overwritten in
software[^4].

#### Read-only filesystems

A read-only file system is a type of filesystem that prohibits altering data to
ensure integrity and stability of the files. The primary purposes for read-only
filesystems are: prohibiting unauthorized or accidental modifications,
improving system reliability and enhancing security. Read-only filesystem rely
on file system permissions to restrict write access. An attempt to modify files
would result in permission denied error types[^5].

Some filesystems are inherently read-only by design, examples are:
* ISO 9660 - industry standard, read-only media format designed for
compact-disk read-only memory (CD-ROM)[^6].
* SquashFS - compressed, read-only filesystem for archival use on Linux.
Intended for scenarios where low overhead is needed[^7].
* EROFS - stands for "Enhanced Read-Only File System", a general-purpose,
flexible filesystem focused on runtime-performance[^8].

Read-only file systems should not be misconstrued as write-protection.
Write-protection prevents writing or modifying data thus making it immutable,
it is often associated with
[physical storage devices](#read-only-physical-media). Read-only on the other
hand limits data access for reading purposes only[^9].

#### Mounting as read-only on Linux

In context of attaching storage devices on Linux, a read-only is a storage
configuration mechanism that ensures no modification can be done to attached
medium, enhancing security and integrity. Mounting a filesystem as read-only
attaches storage with read-only configuration to Linux directory structure.
This configuration acts as An additional layer of protection served by the
system. Linux does allow read-writable filesystems (e.g. ext4) to be
mounted as read-only[^10].

#### Read-only filesystem permission

Read-only is a file-system permission, allowing for reading and copying the
data, but prohibits modification and appending data. A file, directory or
[entire disk](#read-only-physical-media) can be `read-only`[^11].

A read-only file is any file with read-only attribute enabled. Such files can
be read but cannot be modified nor removed. A file might be read-only on a file
level or directory level. If I directory read-only permission is set, all the
files in directory inherit that permission[^12]. It is worth noting, that each
filesystem might handle read-only permissions differently, thus "read-only"
should be thought of as a concept, rather how it is implemented. For example,
NTFS supports six basic groups of permission types that include[^13]: read,
write, list folder contents, read & execute, modify and full control. The
permissions are granted as needed. This means that read-only is a combination
of read permission and lack of write permission.

#### Immutable storage concept

Immutable storage is a term related to "read-only" concept. It is a storage
protocol that ensures stored data cannot be altered within a set or indefinite
amount of time. The time aspect in this definition means, that while it is
possible to create immutable storage for indefinite amount of time, it is
hardly needed as such storages are often used for limited time. The term
"immutable" comes from object-oriented programming, which defines immutable
objects as object which state cannot be changed after it's created.
Immutability can be implemented at various levels of storage stacks, based on
both hardware and software solutions[^14].

One of the immutability implementations is WORM (Write Once, Read Many)
principle. On the other hand, a direct implementation of WORM are
[read-only physical media](#read-only-physical-media). WORM principle ensures
once data is written it cannot be altered or removed. Immutability is also
often related to technologies like snapshotting or immutable filesystems[^15].

#### Immutable Linux OS

Immutable Linux operating systems are aimed to introduce reliable, more secure
approach to Linux. For such systems, the core components like kernel, system
libraries or critical system files are read-only and cannot be modified
permanently. Any changes made to the core system components are lost when
system reboots, but user information is preserved. The advantages of
immutability are:
* increased security - modifications to installed system structure should not
be possible by design,
* easy maintenance - updates are made via atomic upgrades.

These types of systems are updated via creating new OS instance,
deploying it and switching over to the new one. This process is referred to as
"image-based-upgrade"[^16]. In immutable Linux systems, user data is preserved.
It is achieved via various mechanisms including:
* writable overlay layer - this is useful for system directories like `/etc` to
allow modifications to various configurations in a controlled manner.
* separate writable partitions - it is a common practice to put `/home`
directory on separate, writable partition.

These mechanisms also allow for user data to be preserved across the system
updates[^17]. Updates are done alongside reboot, the architecture ensures that
in case of failure in updating the system, one can easily revert system to
previous state. There are multiple ways of handling package installation on
immutable distributions. One of the approaches is to use containerization for
applications to ensure they are isolated from core system[^18]. Some examples
of immutable Linux distributions are: Fedora CoreOs, SUSE MicroOS,
Fedora Silverblue or NixOS. Each distro has its own approach and technology
stack that ensure immutability, e.g. Fedora OSes and SUSE MicroOS use
rpm-ostree[^19]. The `libostree` (a newly proposed name for rpm-ostree)
implements principle of transactional updates and rollbacks. It is similar to
Git as it stores checksums per file and stores them in a content-addressed
storage system. OSTree uses hard links to manage files, thus they must be
immutable by design to avoid corruptions across different versions[^20].

#### Immutable vs stateless

`Stateless` is a design principle in which system (not essentially operating
system) or application does not retain any user session information in between
interactions with stateless entity. Each interaction is independent, it
requires full context needed to perform certain action[^21]. Stateless systems
act like they were just were re-deployed from ground up. Such systems never
store any data on persistent storage, instead they rely on receiving
configuration during runtime via various mechanisms[^22]. Immutability and
statelessness should not be confused. Immutability ensures a system cannot be
changed after deployment, statelessness means a system can be entirely replaced
without concern for local state persistence[^23]. The difference between
stateless systems and immutable systems is that stateless system is designed to
be unmodifiable as a whole. Immutable systems on the other hand, ensure that
only core of the system cannot be modified, but some user data is preserved.

[^1]: [read-only](https://encyclopedia2.thefreedictionary.com/read+only)
[^2]: [what-is-rom](https://umatechnology.org/what-is-rom-how-read-only-memory-works-in-computers/)
[^3]: [optical-storage-devices](https://www.igcseict.info/theory/3/optic/index.html)
[^4]: [how-to-fix-sd-card-showing-as-read-only](https://www.stellarinfo.com/blog/sd-card-showing-read-only/)
[^5]: [read-only-file-system](https://www.sliksafe.com/blog/read-only-file-system)
[^6]: [iso-9660](https://www.ibm.com/docs/en/i/7.5?topic=formats-iso-9660)
[^7]: [squashfs-4.0-filesystem](https://docs.kernel.org/filesystems/squashfs.html)
[^8]: [erofs-enhanced-read-only-file-system](https://docs.kernel.org/filesystems/erofs.html)
[^9]: [is-write-protect-the-same-as-read-only](https://www.lenovo.com/au/en/glossary/write-protect/)
[^10]: [create-read-only-filesystems-in-linux](https://labex.io/tutorials/linux-create-read-only-filesystems-in-linux-415253)
[^11]: [read-only](https://www.computerhope.com/jargon/r/readonly.htm)
[^12]: [what-is-a-read-only-file](https://www.lifewire.com/what-is-a-read-only-file-2625983)
[^13]: [ntfs-permissions](https://www.permissionsreporter.com/ntfs-permissions)
[^14]: [what-is-immutable-storage](https://www.ibm.com/think/topics/immutable-storage)
[^15]: [immutable-file-systems](https://www.ctera.com/blog/immutable-file-systems-ctera-worm-storage/)
[^16]: [Understanding-immutable-linux-os](https://kairos.io/blog/2023/03/22/understanding-immutable-linux-os-benefits-architecture-and-challenges/)
[^17]: [immutable-linux](https://dev.to/khozaei/immutable-linux-4a4a)
[^18]: [what-is-immutable-linux](https://www.zdnet.com/article/what-is-immutable-linux-heres-why-youd-run-an-immutable-linux-distro/)
[^19]: [the-future-is-minimal-and-immutable](https://sonalake.com/latest/the-future-is-minimal-and-immutable-a-new-generation-of-operating-systems/)
[^20]: [libostree](https://ostreedev.github.io/ostree/)
[^21]: [stateful-vs-stateless](https://www.ninjaone.com/blog/stateful-vs-stateless-architecture/)
[^22]: [factory-reset-stateless-systems-reproducible-systems-verifiable-systems](https://0pointer.net/blog/projects/stateless.html)
[^23]: [stateless-linux](https://konfou.xyz/posts/stateless-linux/)

### Checksum verification

Checksum is a redundancy check for detecting variations in data or data
streams. Checksums are created as result of calculating binary values of a
block or packet of data using dedicated algorithms. Comparing checksums allows
for verifying data integrity, yet it's truthfulness is dependent of algorithm
used[^1].

#### Checksums and hash codes

Transforming a portion of data of any size, into a code with predefined size is
referred to as hashing process. A result of performing a hash function is
output in form of a hash code (or simply hash). Hash codes are irreversible by
definition, in theory a hash cannot be used to recreate source data.

Checksums are based on hash codes concept, yet they serve different purposes.
Checksum algorithms are optimized for calculation speed in expense of security.
Checksums are focused on checking data integrity, serving as a digital
fingerprints. A hash codes and cryptographic functions are much broader concept
that focuses on security and authentication[^2].

#### Common hashing algorithms

Common hashing algorithms include[^3]:
* MD-5 - created in 1991, but now considered compromised as it was discovered
how to crack it. A successful collision attacks against it were
demonstrated[^4].
* SHA family - developed by US government, currently an industry standard.
Most recent SHA-3 algorithm uses sponge construct mechanism, which enhances
it's security by processing data with random-like transformations[^5].

Hashing algorithm produce hash values, yet they are often used as a way to
verify data integrity, serving a role of a checksum. This is why it is not
uncommon to see an output of hashing algorithms being referred to as checksum.

#### Hash verification in chain of trust context

Hashing functions can be used as a part of chain of trust mechanism.
Particular example is Google's Verified Boot found on Android based devices.
Verified boot cryptographically verifies executable code and data as the device
boots. It does so for both files and partitions using multiple mechanisms, one
of them being [dm-verity](#dm-verity). In Verify Boot implementation hashes
are stored on dedicated partitions and are signed by the root of trust[^6].

#### Extending chain of trust to OS

A supplementary integrity checks can also be performed on OS level. Following
are tool examples that can help perform additional security checks.

`debsums` is a utility for verifying Debian package files against their
checksums. The MD-5 algorithm is used in the process. `debsums` is primarily
intended for determining if installed files were modified or damaged. It also
serves limited usage as a security tool[^7].

`debcheckroot` is an utility that can perform trusted verification of root file
system by comparing package content with the files on a disk. It performs
similar role to `debsums`, the difference is `debsums` uses locally stored
md5sums,`debcheckroot` on the other hand can verify checksums with multiple
source types: online, CD, DVD, etc. While this might make it more reliable,
it's primary purpose are integrity checks checks and it's not meant to be used
as a security tool[^8].

`AIDE` is a file structure integrity checker software. AIDE works by creating
database storing file hashes and permissions, which is later used to verify
integrity of the files. The files which are monitored can be specified via
editing configuration file[^9].

[^1]: [checksum-definition](https://www.linfo.org/checksum.html)
[^2]: [hash-code-vs-checksum](https://www.baeldung.com/cs/hash-code-vs-checksum)
[^3]: [hashing-algorithm-overview](https://www.okta.com/identity-101/hashing-algorithms/)
[^4]: [on-collsons-for-md5](https://web.archive.org/web/20170517115509/http://www.win.tue.nl/hashclash/On%20Collisions%20for%20MD5%20-%20M.M.J.%20Stevens.pdf)
[^5]: [the-state-of-hashing-algorithms](https://medium.com/@rauljordan/the-state-of-hashing-algorithms-the-why-the-how-and-the-future-b21d5c0440de)
[^6]: [verify-boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot)
[^7]: [debsums](https://manpages.ubuntu.com/manpages/trusty/man1/debsums.1.html)
[^8]: [debcheckroot](https://www.elstel.org/debcheckroot/index.html)
[^9]: [aide](https://aide.github.io/)

### dm-verity

Device Mapper (DM) is a Linux kernel component for managing logical
volumes[^1]. Device Manager allows mapping physical block devices, to create
virtual block devices[^2].

Device-Mapper's verity (`dm-verity`) provides a read-only target (layer)
providing integrity checking of block devices using kernel crypto API[^3].

`dm-verity` allows for detection if the data has been tampered with at binary
level, a single bit flipped should have impact in hash changing. `dm-verity`
splits block device into blocks and calculates their hashes, which can be
stored on separate (non dm-verity protected) or in unallocated space at the end
of data partition.`dm-verity` follows Merkle tree (hash tree) structure, where
each node (leaf) is labeled with hash of data block. Non-leaf nodes are labeled
with hash of the labels of their child-nodes. Validation proceeds from the
leaves level, up to the root hash, where final validation happens. A simplified
structure is shown on diagram below

```text
                                           Block 8
                                          /
                                Hash H-2-2
                               /          \
                              /            Block 7
                |  Hash H-2  |
                |H-2-1..H-2-2|
               /              \            Block 6
              /                \          /
             /                  Hash H-2-1
            /                             \
           /                               Block 5
|Root hash|
|H-1..H-2 |
           \                               Block 4
            \                             /
             \                  Hash H-1-2
              \                /          \
               \              /            Block 3
                |  Hash H-1  |
                |H-1-1..H-1-2|
                              \            Block 2
                               \          /
                                Hash H-1-1
                                          \
                                           Block 1
```

This structure ensures data integrity as no change can be made without altering
root hash[^4]. In `dm-verity` scheme data is verified as it's being read, any
variations would cause I/O errors[^5].

The `dm-verity` integrity control has disadvantage that limits the storage to
be read-only, which might be challenging to work with in fully-fledged
operating systems. Updates must be performed offline and hashes need to be
recalculated. This works well in embedded environment, where devices are
expected to have identical disk layout[^4].

`dm-verity` is used on Android based devices (since Android 4.4) as a part of
`verified boot`, Google's chain of trust implementation. During boot process,
each stage is being verified prior to executing[^6].

[^1]: [device-mapper-resource-page](https://sourceware.org/dm/)  
[^2]: [dm-verity-rootfs-integrity](https://archive.fosdem.org/2023/schedule/event/image_linux_secureboot_dmverity/attachments/slides/5559/export/events/attachments/image_linux_secureboot_dmverity/slides/5559/DM_Verity.pdf)  
[^3]: [linux-kernel-documentation](https://docs.kernel.org/admin-guide/device-mapper/verity.html)  
[^4]: [dm-verity-in-embedded-device-security](https://www.starlab.io/blog/dm-verity-in-embedded-device-security)  
[^5]: [dm-verity](https://docs.qualcomm.com/bundle/publicresource/topics/80-88500-4/80_DM_verity.html)  
[^6]: [an-introduction-to-dm-verity-on-android](https://technotes.kynetics.com/2018/introduction-to-dm-verity-on-android/)

### LUKS drive encryption

Device encryption aims to protect storage media from unauthorized data access
and modifications. Encrypted storage devices require authentication
(e.g. password) to access the media. The limitation of this technology is that
the drive is protected only if the host is turned off or the storage media has
not yet been unlocked. Once authenticated, the data can be accessed, even if
the host itself is in locked state[^1].

LUKS (Linux Unified Key Setup) is a specification for storage device
encryption. In the implementation a Linux kernel device mapper's `dm-crypt`
module is used to perform low level encryption and decryption operations on
user data. On the other hand, user-level operations are performed via
`cryptsetup` utility[^2]. LUKS format can be used to encrypt partitions,
multiple device RAID arrays, LVM partition or block devices. LUKS layout
consists of three main components:
* LUKS header - stores encryption related metadata e.g. utilized algorithm or
keys. Typically located at the beginning of the partition/storage-media, but
it is also possible to use "detached" header and store it elsewhere. If the
header gets damaged or lost, the data is irreversibly lost[^3].
* "key material" area - this is where up to 8 encoded variants of the master
key are stored. The principle of this mechanism can be compared to deposit
boxes at a bank. Rather than using user key to decode the data, the user key is
used to access deposit box which contains the master key used to decrypt the
data. This ensures multiple users can have access to the data, without sharing
the master key. A user key can either be a passphrase or a key file, which when
stored on a external storage media, can serve as a physical key.
* ciphered user data.

#### Integrity protection with dm-integrity

`cryptsetup` LUKS2 based devices by default ensure only confidentiality
protection. An additional integrity protection can be configured directly in
`cryptsetup`. If it is enabled, an additional `dm-integrity` device is added to
virtual device stack and `dm-crypt` layer is placed on top of it. The downside
is that available storage space is reduced as it is necessary to allocate
additional memory for integrity tags (metadata and journal)[^4].

`dm-integrity` integrity is based on an "atomic-write" (all-or-nothing)
principle. This means that in case of a system crash both data and integrity
tag must get written. `dm-integrity` ensures that by using journals. Sector
data get first written into a journal, then the journal is committed and both
data and integrity tags are copied to their respective locations. The
`dm-integrity` can either work as a standalone target or alongside `dm-crypt`
target. In standalone mode it is used for silent data corruption detection that
can be caused for e.g. by disk errors. In case of second mentioned mode, the
`dm-crypt` is responsible for generating integrity tags. These are then passed
to `dm-integrity`. The `dm-integrity` role is to detect data tampering, and if
so, return I/O errors rather than the corrupted data.

#### TPM support

LUKS2 encryption can be combined with tools like `systemd-cryptenroll` or
`clevis luks bind`.

`systemd-cryptenroll` is a tool for enrolling hardware security tokens into
LUKS2 encrypted storages. The tool works by storing meta-information in LUKS2
JSON token area[^6]. The `systemd-cryptestup` service is then used to
automatically attach and detach encrypted block devices[^7].

`Clevis` is a pluggable framework for automated encryption and decryption of
LUKS volumes. It uses so called PINs, a plugins that implement automated
decryption. The PIN can be later binded to a LUKS volume so it is automatically
unlocked via various "unlocker" types, including[^7]:
* dracut - to unlock volumes during early boot.
* initramfs - same principle as for `dracut`,
* UDisk2 - a desktop session utility, useful when connecting external storages.
Its role is to unlock inserted removable storage medias automatically, without
user intervention.

The two encryption tools differ on how they operate. The `systemd-cryptenroll`
is for simply enrolling TPM keys to LUKS while other systemd services handle
unlocking. Its advantage is no need for extra tooling at boot as decryption
is handled directly by systemd. `Celvis` does act as an additional layer on top
of `LUKS` and `cryptsetup`. It is an additional tool that must function at boot
time, but its advantage is support for more unlocking methods.

[^1]: [device-encryption](https://riseup.net/ca/security/device-security/device-encryption)
[^2]: [disk-encryption-user-guide](https://docs.fedoraproject.org/en-US/quick-docs/encrypting-drives-using-LUKS/)
[^3]: [what-is-luks-and-how-does-it-work](https://www.sysdevlabs.com/articles/storage-technologies/what-is-luks-and-how-does-it-work/)
[^4]: [cryptsetup](https://man7.org/linux/man-pages/man8/cryptsetup.8.html)
[^5]: [dm-integrity](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html)
[^6]: [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
[^7]: [systemd-crypteup](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptsetup.html)
[^8]: [clevis](https://github.com/latchset/clevis)

### CVMs

Confidential computing is a concept in which workloads are isolated from the
environment they run on, in order to assure confidentiality. Confidential
Virtual Machines (CVMs) put this theory into practice, assuring workloads and
data are isolated from the host system unless explicit access is granted[^1].

Confidential VMs use hardware-based memory encryption which is supported by
technologies including AMD SEV or Intel TDX. CVMs have benefits of[^2]:
* isolation - keys reside solely in dedicated hardware and are inaccessible to
hypervisor,
* attestation - VM identity and state can be verified to ensure integrity.

Usage of CVMs can be used as a security strategy preventing data or workload
exposition. CMVs follow Trusted Execution Environment (TEE) principle, to
provide safe and isolated environments to protect user resources from
unwanted access[^3]. Utilization of confidential virtual machines can improve
overall security of a system (infrastructure) due to following factors:
* adding additional, hardware based encryption layer,
* separating host from VM reducing risk of malware infection,
* preventing side channel attacks like cold-boot.

It should be noted, that while CVMs can greatly improve security, it is only
beneficial at VM level, not for the host itself. CVM usage: can reduce
manageability by increasing overhead, increase cost and was proven of being
difficult to attest[^4]. Moreover, CMVs are not protected from a malicious or
compromised host[^5], thus it is equally important to ensure the security of
the underlying infrastructure and implement additional layers of protection to
mitigate potential risks.

#### References

[^1]: [introduction-to-confidental-virtual-machines](https://www.redhat.com/en/blog/introduction-confidential-virtual-machines)
[^2]: [confidential-vm-overview](https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview)
[^3]: [few-key-points-of-confidential-vm](https://www.naukri.com/code360/library/few-key-points-of-confidential-vm)
[^4]: [ernax-and-confidential-vms-compated](https://enarx.dev/assets/files/Enarx_and_Confidential_VMs_compared-9d0e599aaf63f5d1c0c873e37094251e.pdf)
[^5]: [confidential-vms-hacked-via-new-ahoi-attack](https://www.securityweek.com/confidential-vms-hacked-via-new-ahoi-attacks/)

### ISOs

ISO is format of disk file image containing exact duplicate of data from source
disk. ISO disk images are common way to share software (including OS)
installation media[^1]. This chapter will focus on various scenarios in which
installation media could be tampered with, leading to compromised software
being installed.

`.iso` images cannot be modified by mounting them and modifying the files, yet
there are ways to "modify" .iso image. One of the ways is repackaging, this
means extracting image contents, performing modifications and repackaging
contents into new disk image file. It is important to always check signatures,
as described in [checksum verification chapter](#checksum-verification)[^2],
to verify integrity of disk images. If package is skillfully repackaged, it's
execution won't be prohibited by secure boot mechanism[^3]. Another way of
compromising read-only attribute of `iso` images is flashing such image onto
physical media.

#### Verifying boot media with secure-boot

Kicksecure would like to utilize secure boot to verify distributed installation
media, yet there are limitations to this technology which do not allow it:
* Booting `.iso` file directly, rather than flashing the contents onto physical
media, is possible with boot-loaders like GRUB[^4]. Yet, such image cannot be
cryptographically verified as a whole. GRUB verifies contents at
component-level. This approach might still lead to executing repackaged `iso`.
* Vast majority of x86 based hardware comes preloaded with Microsoft keys, this
means that when secure boot is enabled, only Microsoft signed binaries are
allowed to run[^5]. It used to be that binaries could be signed only with a
single key, this means that OS vendors couldn't sign binaries themselves as
they would have been prohibited from executing. As of 2014 a binary can be
signed by multiple authorities[^6].

#### Modifying ISOs with growisofs

`growisofs` is a linux utility that can append data to
[read-only filesystems](#read-only-filesystems) like ISO9660 and
[read-only physical media](#read-only-physical-media) like DVD+RW. `growisofs`
was originally developed as a frontend to `mkisofs`[^7]. The key factor here,
is that `mkisofs` performs "merging", the output is a new session which gets
written to the end of the image file[^8]. This proves that limited
in-place "modifications" of ISO files are possible.

[^1]: [iso-file-extension](https://fileinfo.com/extension/iso)
[^2]: [iso-image](https://www.lenovo.com/us/en/glossary/iso-image/)
[^3]: [unified-extensible-firmware-nterface/secure-boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#ISO_repacking)
[^4]: [multiboot-usb-drive](https://wiki.archlinux.org/title/Multiboot_USB_drive#Using_GRUB_and_loopback_devices)
[^5]: [SecureBoot](https://wiki.debian.org/SecureBoot)
[^6]: [add-multiple-signature-support](https://web.git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/commit/src/image.c?id=f6115a8045275a0dc138f9088ba018441146e81d)
[^7]: [growisofs](https://linux.die.net/man/1/growisofs)
[^8]: [mkisof](https://linux.die.net/man/8/mkisofs)

