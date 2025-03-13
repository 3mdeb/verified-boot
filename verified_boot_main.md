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

ISO is format of disk file image containing exact duplicate of data from source
disk. ISO disk images are common way to share software (including OS)
installation media[^1]. This chapter will focus on various scenarios in which
installation media could be tampered with, leading to compromised software
being installed.

`.iso` images cannot be modified by mounting them and modifying the files, yet
there are ways to "modify" .iso image. One of the ways is repackaging, this
means extracting image contents, performing modifications and repackaging
contents into new disk image file. It is important to always check signatures,
as described in [checksum verification chapter](#checksum-verification)[^2],
to verify integrity of disk images. If package is skillfully repackaged, it's
execution won't be prohibited by secure boot mechanism[^3]. Another way of
compromising read-only attribute of `iso` images is flashing such image onto
physical media.

#### Verifying boot media with secure-boot

Kicksecure would like to utilize secure boot to verify distributed installation
media, yet there are limitations to this technology which do not allow it:
* Booting `.iso` file directly, rather than flashing the contents onto physical
media, is possible with boot-loaders like GRUB[^4]. Yet, such image cannot be
cryptographically verified as a whole. GRUB verifies contents at
component-level. This approach might still lead to executing repackaged `iso`.
* Vast majority of x86 based hardware comes preloaded with Microsoft keys, this
means that when secure boot is enabled, only Microsoft signed binaries are
allowed to run[^5]. It used to be that binaries could be signed only with a
single key, this means that OS vendors couldn't sign binaries themselves as
they would have been prohibited from executing. As of 2014 a binary can be
signed by multiple authorities[^6].

[^1]: [iso-file-extension](https://fileinfo.com/extension/iso)
[^2]: [iso-image](https://www.lenovo.com/us/en/glossary/iso-image/)
[^3]: [unified-extensible-firmware-nterface/secure-boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot#ISO_repacking)
[^4]: [multiboot-usb-drive](https://wiki.archlinux.org/title/Multiboot_USB_drive#Using_GRUB_and_loopback_devices)
[^5]: [SecureBoot](https://wiki.debian.org/SecureBoot)
[^6]: [add-multiple-signature-support](https://web.git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/commit/src/image.c?id=f6115a8045275a0dc138f9088ba018441146e81d)

### VMs
- 939-946    Part 3: OS and VMs
