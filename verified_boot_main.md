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

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
