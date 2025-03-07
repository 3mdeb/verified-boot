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
<!-- Describe differences in verified boot between Legacy / UEFI / Heads -->
#### Legacy

<!-- implementation specific? -->

#### UEFI

<!-- UEFI Secure Boot? -->

#### Heads

<!-- - http://osresearch.net/ not much info here -->


### Firmware protections against changing settings in its UI

### Firmware protections against changing firmware's flash chip
- 811-831    "Write Protection"

### Intel Boot Guard / AMD Platform Secure Boot



#### Intel Boot Guard

<!-- - Intel ISA doesn't mention BG. Possibly there is some info there, but it's
too low level to be used https://cdrdv2.intel.com/v1/dl/getContent/671200 -->


Intel Boot Guard is a technology that implements a S-RTM and a RTV in hardware.

The hardware-based RTV works by verifying the Initial Boot Block (IBB)
using OEM keys, that are saved in the CPU itself and can be fused to make them
permamently read-only. This procedure makes it impossible to boot any firmware
that is not signed (trusted) by the owner of the OEM keys.

<!-- based on weird chinese site? Can't change the language https://edc.intel.com/content/www/cn/zh/design/ipla/software-development-platforms/client/platforms/alder-lake-desktop/12th-generation-intel-core-processors-datasheet-volume-1-of-2/010/boot-guard-technology/
-->

#### AMD Platform Secure Boot

<!-- - Platform Security Processor (PSP)
- https://doc.coreboot.org/soc/amd/psp_integration.html
- https://ioactive.com/exploring-amd-platform-secure-boot/ - might be great,
but I don't know about the credentialibity of this site
- AMD developer guide that describes the Platform Secure Processor https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/programmer-references/52740_16h_Models_30h-3Fh_BKDG.pdf


-->

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
