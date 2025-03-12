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

Role-Based boot is a term proposed by Kicksecure, it is a concept of booting
operating system into different modes based on user roles in order to enhance
security. Each role (mode) should have limited variety of workloads it's
allowed to perform and limited access to resources. This is similar to
principle of least privilege. The aim for role-base boot concept is to develop
more secure and flexible OS environments by tailoring boot models to specific
user roles for performing permissible range of tasks.

Role-based boot is implemented in Kicksecure and Whonix operating systems.
Currently supported boot modes are[^1]:
* `PERSISTENT mode` - intended for performing daily activities (browsing,
email, chat) with write access only for `/home` directory.
* `LIVE mode` - serves same usage as `PERSISTENT mode` but changes are not
persistent between system reboots.
* `PERSISTENT mode SYSMAINT` - intended only for performing system maintenance
with global write access.

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

### Read-only/discardable-file-systems

### Checksum verification

### dm-verity

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
