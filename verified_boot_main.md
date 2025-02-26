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

According to NIST [^NIST_Trust]:
> A characteristic of an entity that indicates its ability to perform certain
functions or services correctly, fairly and impartially, along with assurance
that the entity and its identifier are genuine.

[^NIST_Trust]: https://csrc.nist.gov/glossary/term/trust

#### Root of Trust (RoT)
According to NIST [^NIST_Rot]:
> A starting point that is implicitly trusted.

*Implicitly trusted* means, that the trust towards the **Root of Trust**
inherent, unprovable, and serves as the core or basis upon which security
mechanisms are built.

A more practical definition from NIST [^NIST_Rots]
> Highly reliable hardware, firmware, and software components that perform specific, critical security functions. Because roots of trust are inherently trusted, they must be secure by design. Roots of trust provide a firm foundation from which to build security and trust.

The trust towards the **Root of Trust** is undeniable and it cannot be proven.
Otherwise the software, hardware, or person proving, that the
**Root of Trust** can be relied on, would be the actual
**Root of Trust**.

[^NIST_Rot]: https://csrc.nist.gov/glossary/term/rot
[^NIST_Rots]: https://csrc.nist.gov/glossary/term/roots_of_trust

#### Chain of Trust (CoT)
According to NIST [^NIST_Cot]:
> A method for maintaining valid trust boundaries by applying a principle of transitive trust, where each software module in a system boot process is required to measure the next module before transitioning control.

[^NIST_Cot]:

### Categorization of chains/roots of trust

#### RTM (Root of Trust for Measurements)

#### RTR (Root of Trust for Reporting)

#### RTS (Root of Trust for Storage)

#### RTV (Root of Trust for Verification)

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
