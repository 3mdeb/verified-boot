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

### ISOs

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

CVMs can greatly improve overall security of the system as a whole, due to
following factors:
* adding additional, hardware based encryption layer,
* separating host from VM reducing risk of malware infection,
* preventing side channel attacks like cold-boot.

#### References

[^1]: [introduction-to-confidental-virtual-machines](https://www.redhat.com/en/blog/introduction-confidential-virtual-machines)
[^2]: [confidential-vm-overview](https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview)
