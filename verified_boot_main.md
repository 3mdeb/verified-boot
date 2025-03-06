# Verified Boot

## 1. Introduction
- 16-41 "What is Verified Boot?
- 133-149 "How does Verified Boot work?"
- 150-159 "Applicability of Verified Boot"
- 160-165 "Who uses Verified Boot?"
- 166-174 "What are the dangers of Verified Boot?"
- 175-192 "When the Verification is over?"
- 869-874 "See Also

### Trust, chain of trust, root of trust

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

Checksum as a concept, is a redundancy check for detecting variations in data.
Checksums are created as result of calculating binary values of a block or
packet of data using sophisticated algorithms. Comparing checksums allows for
verifying data integrity, yet is truthfulness is dependent of algorithm
used[^1].

Checksums values come in form of unique, fixed string of characters referred to
as hash. Exact form of hash is dependent on algorithm used. Checksum algorithms
ensure even tiniest changes made to a block of data, would result in checksum
value changing completely. This property makes them easy to compare without
need for any additional components. Common algorithms include: sha-256, md5 or
sha-1[^2].

#### Checksum verification in chain of trust context

Checksum verification can be used as a part of chain of trust mechanism.
Particular example is Google's Verified Boot found on Android based devices.
Verified boot cryptographically verifies executable code and data as the device
boots. It does so for both files and partitions using multiple mechanisms, one
one of them being [dm-verity](#dm-verity). In Verify Boot implementation hashes
are stored on dedicated partitions and are signed by the root of trust[^3].

#### debsums

A supplementary integrity checks can also be performed on OS level.
`debsums` is an utility for verifying debian package files against their
checksums. It is primarily intended for determining if installed filed were
modified or damaged. It also serves limited usage as a security tool[^4].

#### References

[^1] [Checksum Definition](https://www.linfo.org/checksum.html)
[^2] [Exploring Checksums: Types, Uses, And Verification Methods](https://linuxsecurity.com/features/what-are-checksums-why-should-you-be-using-them)
[^3] [Verify Boot](https://source.android.com/docs/security/features/verifiedboot/verified-boot)
[^4] [debsums](https://manpages.ubuntu.com/manpages/trusty/man1/debsums.1.html)

### dm-verity

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
