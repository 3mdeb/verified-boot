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

### dm-verity

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
keys. Typically located at the beginning of the partition/storage-media but
also it also possible to use "detached" header and store it elsewhere. If the
header get's damaged or lost, the data is irreversibly lost[^3].
* "key material" area - this is where up to 8 encoded variants of the master
key are stored. The principle of this mechanism can be compared to deposit
boxes at a bank. Rather than using user key to decode the data, the user key is
used to access deposit box which contains the master key used to decrypt the
data. This ensures multiple users can have access to the data, without sharing
the master key. A user key can either be a passphrase or a key file, which when
stored on a external storage media, can serve as a physical key.
* ciphered user data.

[^1]: [device-encryption](https://riseup.net/ca/security/device-security/device-encryption)
[^2]: [disk-encryption-user-guide](https://docs.fedoraproject.org/en-US/quick-docs/encrypting-drives-using-LUKS/)
[^3]: [what-is-luks-and-how-does-it-work](https://www.sysdevlabs.com/articles/storage-technologies/what-is-luks-and-how-does-it-work/)

Why encrypt drive?
What's LUKS?
Where is it implemented?
How it works?
What's dm-integirty?
How is dm-integrity used in the process?

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
