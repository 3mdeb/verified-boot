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
- `coreboot` - implements verified boot, calls the feature `vboot` [^coreboot_vboot]
- `skiboot` - implements verified boot and exposes the API as the
  Secure and Trusted Boot Library [^skiboot_libstb]
- `seabios` - exposes the `1Ah` BIOS interrupt, an ABI defined by the TCG[^TCG_1ah]
  that allows interacting with TPM and performing verification and measurements
  by the next launched component[^seabios_1ah]

[^wikipedia_bic]: https://en.wikipedia.org/wiki/BIOS_interrupt_call
[^coreboot_vboot]: https://doc.coreboot.org/security/vboot/index.html
[^TCG_1ah]: TCG PC Client Specific Implementation Specification for Conventional BIOS, section https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
[^seabios_1ah]: https://mail.coreboot.org/pipermail/seabios/2011-April/001609.html
[^skiboot_libstb]: https://open-power.github.io/skiboot/doc/stb.html

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
come signed using them. The Debian Wiki [^Debian_sb] explains how this fact,
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

 [^Dasharo_password]: Dasharo menu overwier, User password management, https://docs.dasharo.com/dasharo-menu-docs/overview/#user-password-management
 [^MSI_password]: MSI DT BIOS Manual, under "Security", https://www.msi.com/support/technical_details/DT_BIOS_Manual
 [^system76_password]: System76 Technical Documentation, Security, https://tech-docs.system76.com/models/addw1/setup-specs.html#security
 [^Gigabyte_password]: Gigabyte BIOS Setup User's Guide, Chapter 1, under "Security", https://download.gigabyte.com/FileList/Manual/server_manual_r121-x30_bios_e_1.0.pdf

### Firmware protections against changing firmware's flash chip

The processes of verified boot and measured boot can be used to detect that
the system's security might have been compromited and react to it accordingly.

Protecting the firmware's flash chip from being modified, on the other hand,
is a precaution that might save the device from being compromited altogether.
Making the chip read only should make it impossible to add an untrusted
component to the boot process. Such protections only apply to modifying the
flash chip via the integrated programmer that can be operated by the CPU
and the software running on it. They don't protect the flash chip from being
reprogrammed by physically connecting an external programmer device to it.

On the example of Intel platforms, the supported protections are described
in the chipset Platform Controller Hub datasheets and consist of three
mechanisms:

- Flash Descriptor Master Region [^Intel_series_9_pch_5-26-2-1]
  - Defines the structure of firmware regions
  - Controls the read and write access to the regions
  - The *Master* [^Intel_series_9_pch_5-26-2-1] of the region can access it
    no matter the access setting
  - The CPU is the *Master* of the BIOS region, so this mechanism
    is not enough to protect the BIOS from malicious software
- Global Write Protection [^Intel_series_9_pch_5-26-5-1]
  - Blocks writes to the whole SPI chip
  - Can be turned off after booting by System Management Mode code
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

The AMD Platform Secure Boot[^AMD_PSB], also called AMD Hardware Validated Boot[^AMD_HVB] on data
center processors, provides the Hardware RTM and RTV thanks to the
`AMD Secure Processor (ASP)`, which is logically isolated from the CPU.
The ASP executes the `ASP boot loader code` - a read only code embedded within
the ASP, which verifies an initial part of the firmware called the `Secure Loader (SL)`
using keys fused into the CPU. Verifying the SL makes it the second link of the CTV.
The Secure Loader then extends the
Chain of Trust for Verification by verifying the rest of the BIOS firmware.

[^AMD_HVB]: https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/5th-gen-amd-epyc-processor-architecture-white-paper.pdf
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
