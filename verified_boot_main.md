# Verified Boot

## 1. Introduction
- 16-41 "What is Verified Boot?
- 133-149 "How does Verified Boot work?"
- 150-159 "Applicability of Verified Boot"
- 160-165 "Who uses Verified Boot?"
- 166-174 "What are the dangers of Verified Boot?"
- 175-192 "When the Verification is over?"
- 869-874 "See Also

The purpose of this section is to define the fundamental concepts and key
terminology that will be utilized throughout the document.
A clear understanding of them is essential for ensuring consistency and
precision throughout the document.

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

> A starting point that is implicitly trusted.

~ NIST IR 8320, Appendix H - Glossary, under "root of trust" [^NIST_ir8320]

*Implicitly trusted* means, that the trust towards the **Root of Trust**
inherent, unprovable, and serves as the core or basis upon which security
mechanisms are built.

> Highly reliable hardware, firmware, and software components that perform specific, critical security functions. Because roots of trust are inherently trusted, they must be secure by design. Roots of trust provide a firm foundation from which to build security and trust.

~ NIST SP 800-172, Appendix A, under "roots of trust" [^NIST_sp800-172]

> An element that forms the basis of providing one or more security-
specific functions, such as measurement, storage, reporting,
recovery, verification, update, etc. A RoT is trusted to always
behave in the expected manner because its misbehavior cannot be
detected and because its proper functioning is essential to providing
its security-specific functions

~ NIST SP 800-193, Appendix B - Glossary, under "Root of Trust (RoT)" [^NIST_sp800-193]

> A component (software, hardware, or hybrid) and a computing engine that
constitute a set of unconditionally trusted functions. An RoT must always behave in an expected manner
because its misbehavior cannot be detected.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155]


The trust towards the **Root of Trust** is undeniable and it cannot be proven.
Otherwise the software, hardware, or person proving, that the
**Root of Trust** can be relied on, would be the actual **Root of Trust**.

#### Chain of Trust (CoT)

> A Chain of Trust (CoT) is a sequence of cooperative elements which
are anchored in a Root of Trust (RoT) that extend the trust boundary
of the current element by conveying the same trust properties to the
next element when it passes it control. The result is both elements
are equally able to fulfill the trusted function as though they were a
single trusted element. This process can be continued, further
extending the chain of trust. Once control is passed to code which is
not, or cannot be, verified then the Chain of Trust has ended. This is
also referred to as passing control to a non-cooperative element.

~ NIST SP 800-193, Appendix B - Glossary, under "Chain of Trust (CoT)" [^NIST_sp800-193]

> A method for maintaining valid trust boundaries by
applying a principle of transitive trust, where each
software module in a system boot process is required
to measure the next module before transitioning
control.

~ NIST IR 8320, Appendix H - Glossary, under "Chain of Trust (CoT)" [^NIST_ir8320]

### Categorization of chains/roots of trust

> There are three roots of trust in a trusted platform: root of trust for measurement (RTM), root of
trust for reporting (RTR), and root of trust for storage (RTS). They are the foundational elements
of a single platform. These are the system elements that must be trusted because misbehavior in
these normally would not be detectable in the higher layers.

~ NIST IR 8320, Appendix A, section 2, Hardware Root of Trust: Intel TXT and Trusted Platform Module (TPM) [^NIST_sp800-193]

#### RTM (Root of Trust for Measurements)

> An RoT that makes the initial integrity measurement, and adds it to a tam-
per-resistant log. Note: A PCR in a TPM is normally used to provide tamper
evidence because the log is not in a shielded location.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> A computing engine capable of making inherently reliable
integrity measurements. The RTM is the root of the chain of transitive trust for subsequent measurement agents.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155]

The Root of Trust for Measurements is a broad concept that is often separated
into smaller entities like:
- Static Root of Trust for Measurements (S-RTM)
- Code Root of Trust for Measurements (CRTM)
<!-- TODO sometimes called "Core RTM". Definitely needs an explanation
   -->
- Dynamic Root of Trust for Measurements (D-RTM)
- Hardware Root of Trust for Measurements (HRTM)

##### S-RTM (Static Root of Trust for Measurements)

> An RTM where the initial integrity measurement occurs at platform reset.
The S-RTM is static because the PCRs associated with it cannot be re-ini-
tialized without a platform reset.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

##### CRTM (Core Root of Trust for Measurements)

> The first piece of BIOS code that executes on the main
processor during the boot process. On a system with a Trusted Platform Module the CRTM is implicitly
trusted to bootstrap the process of building a measurement chain for subsequent attestation of other
firmware and software that is executed on the computer system

~ NIST SP 800-147, Appendix B Glossary

The Core Root of Trust for Measurements can be divided into two parts:

###### SCRTM (Static Core Root of Trust for Measurements)

> The SCRTM is composed of
elements that measure firmware at system boot time, creating an unchanging set of
measurements that will remain consistent across reboots except for volatile attributes like date
and time.

~ NIST IR8320, section 3.2 - The Chain of Trust (CoT) [^NIST_ir8320]

###### DCRTM (Dynamic Core Root of Trust for Measurements)

> The DCRTM allows a CoT to be established without rebooting the system, permitting
the RoT for measurement to be reestablished dynamically

~ NIST IR8320, section 3.2 - The Chain of Trust (CoT) [^NIST_ir8320]

<!-- TODO Core RTM or Code RTM? -->
##### CRTM (Code Root of Trust for Measurements)

> The instructions executed by the platform when it acts as the RTM. [For-
merly described as “Core Root of Trust for Measurement”. Code Root of
Trust for Measurement is the preferred expansion.] This acronym expansion
is preferred.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

##### D-RTM (Dynamic Root of Trust for Measurements)

> A platform-dependent function that initializes the state of the platform and
provides a new instance of a root of trust for measurement without rebooting
the platform. The initial state establishes a minimal Trusted Computing
Base.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

##### HRTM (Hardware Root of Trust for Measurements)

> An RTM where hardware performs the initial measurement.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> Security should extend across all tiers of the container technology. The current way of
accomplishing this is to base security on a hardware root of trust, such as the industry standard
Trusted Platform Module (TPM). Within the hardware root of trust are stored measurements of
the host’s firmware, software, and configuration data.

~ NIST SP800-190 [^NIST_sp800-190]
<!-- There seems to be no definition from NIST -->
#### RTR (Root of Trust for Reporting)

> An RoT that reliably provides authenticity and non-repudiation services for
the purposes of attesting to the origin and integrity of platform characteris-
tics.

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> A computing engine capable of reliably reporting information
provided by the RTM and its measurement agent(s) or held by the RTS.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155]

#### RTS (Root of Trust for Storage)

> A computing engine capable of maintaining a tamper-evident
summary of integrity measurement values and the sequence of those measurements.

~ NIST SP800-155, section 3.6.4, Appendix B - Glossary [^NIST_sp800-155]

> The combination of an RTC and an RTI

> RTC (Root of Trust for Confidentiality)
An RoT providing confidentiality for data stored in TPM Shielded Locations.

> RTI (Root of Trust for Integrity)
An RoT providing integrity for data stored in TPM Shielded Locations

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

#### RTV (Root of Trust for Verification)

> An RoT that verifies an integrity measurement against a policy

~ Trusted Computing Group Glossary, Version 1.1, rev 1.0 [^TCG_glossary]

> The core RoT for verification (CRTV) is responsible for verifying the first component
before control is passed to it.

~ NIST IR 8320, section 3.2 The Chain of Trust (CoT) [^NIST_ir8320]


[^NIST_sp800-152]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-152.pdf
[^NIST_sp800-155]: https://csrc.nist.gov/files/pubs/sp/800/155/ipd/docs/draft-SP800-155_Dec2011.pdf
[^NIST_sp800-172]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-172.pdf
[^NIST_sp800-190]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
[^NIST_sp800-193]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf
[^TCG_glossary]: https://trustedcomputinggroup.org/wp-content/uploads/TCG-Glossary-V1.1-Rev-1.0.pdf
[^NIST_ir8320]: https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8320.pdf

### The difference between verified boot and measured boot
- 457-465    "Measured Boot vs Secure Boot"

### Difference between integrity and authenticity verification
- 448-450 "Custom Hardware with Specific Keys"
- 574-583 "Verified Boot for User but not for Admin"

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
