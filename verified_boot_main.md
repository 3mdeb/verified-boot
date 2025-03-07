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

<!--
TODO implementation specific? I dont know to form queries for this
-->

#### UEFI

<!--

http://osresearch.net/FAQ/#whats-wrong-with-uefi-secure-boot
https://learn.microsoft.com/en-us/azure/security/fundamentals/secure-boot
 -->

The UEFI specification defines the UEFI Secure Boot protocol as a security
mechanism that can be used as a part of verified boot process. The protocol
allows to verify the authenticity and integrity of UEFI drivers as well as
the operating system before the hand-off.

Verified boot depends on two roots of trust, the Chain of Trust for Measurement
and the Chain of Trust for Verification. To provide verified boot
functionalities a UEFI BIOS has to implement a number of software components
that need to be verified and consequently added to these chains.

##### Hash services

UEFI specification defines the protocols used to locate and access hashing
services provided by software (drivers) or hardware components
[^UEFI_hash_services].

##### Signature Database

The signature database in UEFI is used to manage a list of
trusted and revoked software signatures.

UEFI Secure Boot bases the verification on two types of keys:
- Platform Key
- Key Exchange Keys (KEK)

> The platform key establishes a trust relationship between the platform
owner and the platform firmware. The platform owner enrolls the public half
of the key (PKpub) into the platform firmware. The platform owner can later
use the private half of the key (PKpriv) to change platform ownership or to
enroll a Key Exchange Key. [^UEFI_key_exchange]

The platform key, also called the owner key, is used to verify the KEKs that
are maintained by the firmware and operating system vendors. It is enrolled
during the production of a device by the OEM, but some UEFI BIOSes allow
removing and enrolling a new one.

> Key exchange keys establish a trust relationship between the operating
system and the platform firmware. Each operating system (and potentially,
each 3rd party application which need to communicate with platform firmware)
enrolls a public key (KEKpub) into the platform firmware. [^UEFI_key_exchange]

The Key Exchange Keys are stored in the Signature Database along the trusted
and revoked signatures of UEFI drivers and operating systems. Updates to the
KEKs must be signed using the currently enrolled PK. Similarily, the updates to
the trusted and revoked signature databases must be signed using an enrolled
KEK.

<!-- TODO Continue with what to enroll to the signature databases -->

Microsoft is the official maintainer of UEFI Secure Boot Platform Keys.
Using the default keys means trusting the device's security to Microsoft
which is one of the reasons why some people are sceptic of the
UEFI Secure Boot. [^HEADS_sb_wrong]
<!-- TODO reference some more discussions -->


<!--
A UEFI BIOS needs to manage a signature database[^UEFI_certificate_database]
Key management[^UEFI_key_mgmnt]
Verification services[^UEFI_verify_protocol]
-->

[^UEFI_key_mgmnt]: UEFI Specification Version 2.10 Errata A https://uefi.org/specs/UEFI/2.10_A/37_Secure_Technologies.html#key-management-service
[^UEFI_hash_services]: UEFI Specification Version 2.10 Errata A https://uefi.org/specs/UEFI/2.10_A/37_Secure_Technologies.html#hash-references
[^UEFI_verify_protocol]: UEFI Specification Version 2.10 Errata A https://uefi.org/specs/UEFI/2.10_A/37_Secure_Technologies.html#pkcs7-verify-protocol
[^UEFI_certificate_database]: https://uefi.org/specs/UEFI/2.10_A/32_Secure_Boot_and_Driver_Signing.html#uefi-image-validation
[^UEFI_PK]: https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html#firmware-os-key-exchange-creating-trust-relationships
[^UEFI_key_exchange]: https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html#firmware-os-key-exchange-creating-trust-relationships


[^HEADS_sb_wrong]: http://osresearch.net/FAQ/#whats-wrong-with-uefi-secure-boot
#### Heads

<!--
http://osresearch.net/ not much info here, are there better sources on how
Heads implements verification?
-->


### Firmware protections against changing settings in its UI

Typically two factors are used to authenticate changes in firmware settings
using the UI:
- Physical presence - because the UI is presented on a screen and the inputs
are incoming from an external device it is often safe to assume that a person,
not malicious code, is accessing the settings, and so the changes may be treated
as authenticated
- BIOS Password - in scenarios where a higher security is required most BIOS
firmwares implement a way to set up a password which protects the settings
from being changed[^Dasharo_password][^MSI_password][^system76_password][^Gigabyte_password]

<!--

https://docs.dasharo.com/dasharo-menu-docs/overview/#user-password-management

http://osresearch.net/FAQ/#why-use-linux-instead-of-vboot2
> by moving the verification into the boot scripts we’re able to have a much
  flexible verification system and use more common tools like PGP to sign firmware stages

 -->

 [^Dasharo_password]: Dasharo menu overwier, User password management, https://docs.dasharo.com/dasharo-menu-docs/overview/#user-password-management
 [^MSI_password]: MSI DT BIOS Manual, under "Security", https://www.msi.com/support/technical_details/DT_BIOS_Manual
 [^system76_password]: System76 Technical Documentation, Security, https://tech-docs.system76.com/models/addw1/setup-specs.html#security
 [^Gigabyte_password]: Gigabyte BIOS Setup User's Guide, Chapter 1, under "Security", https://download.gigabyte.com/FileList/Manual/server_manual_r121-x30_bios_e_1.0.pdf

### Firmware protections against changing firmware's flash chip
- 811-831    "Write Protection"

### Intel Boot Guard / AMD Platform Secure Boot

<!-- TODO?? Because the technologies are more or less equivalent, maybe it's
better to describe what they are about here and then show the differences
in naming in the two sections -->

The two technologies are mostly equivalent and serve the purpose of:
- Verifying and Measuring the BIOS firmware
- Providing a Hardware RTM (HRTM) and RTV (HRTV) for the processes
  of verified and measured boot
- Allowing to create uninterrupted Chains of Trust from the hardware up to
  an operating system

The hardware roots of trust consist of:
- A secure storage for enrolling keys by the OEM. Possibly using electronic
fuses[^efuses_wikipedia] that make the keys permamently encoded into the CPU
- Hardware implementations of basic cryptography operations
- A small read-only code for verifying the firmware

#### Intel Boot Guard

<!-- Intel ISA doesn't mention BG. Possibly there is some info there, but it's
too low level to be used https://cdrdv2.intel.com/v1/dl/getContent/671200

-->

Intel Boot Guard is a technology that implements a RTM and a RTV in hardware.
The hardware-based RTV works by verifying the initial part of the firmware
called the `Initial Boot Block (IBB)` using the `Authenticated Code Module (ACM)`
code embedded in the CPU by the manufacturer. The IBB is verified using the OEM
keys, that are also in the CPU itself and can be fused to make them permamently
read-only. The IBB is the second link of the CTV and continues to extend
it.

<!--
better: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html
-->

#### AMD Platform Secure Boot

The AMD PSB[^AMD_PSB] rovides the Hardware RTM and RTV thanks to the
AMD Secure Processor (ASP), which is logically isolated from the CPU.
The ASP executes the `ASP boot loader code`, which verifies an initial part
of the firmware called the `Secure Loader`, using keys fused into the CPU,
making it the second link of the CTV.

<!-- TODO?? Describe the names of equivalent components in Intel/AMD: SINIT/SKINI, IBB, SL etc. -->

[^AMD_PSB]: https://www.amd.com/content/dam/amd/en/documents/products/processors/ryzen/7000/ryzen-pro-7000-security-whitepaper.pdf
<!-- - Platform Security Processor (PSP)
- https://doc.coreboot.org/soc/amd/psp_integration.html
- https://ioactive.com/exploring-amd-platform-secure-boot/ - might be great,
but I don't know about the credentialibity of this site
- AMD developer guide that describes the Platform Secure Processor https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/programmer-references/52740_16h_Models_30h-3Fh_BKDG.pdf


-->
[^efuses_wikipedia]: https://en.wikipedia.org/wiki/EFuse

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
