# User-controlled Verified Boot UEFI Application

## Abstract

The complexity of Verified Boot and Secure Boot solutions lead to significant
amount of problems in regular use, reownership and management of keys, signed
operating systems and their bootloaders. The user interface of the firmware
setup has not evolved in the past years, maintaining the state of
user-unfriendliness of UEFI Secure Boot feature. Addressing the problem
requires a new approach, different than regular forms and checkboxes, that
many (BIOS/hardware) vendors deem sufficient for the majority of their
customers/end-users of the hardware. This document describes a generic
solution for UEFI compliant firmware and systems that simplifies the initial
configuration and reownership of the UEFI Secure Boot feature. A wizard-like
application is proposed, which:

- Automates the operations usually done by hand by the users, which require an
  intermediate understanding of UEFI Secure Boot.
- Guides the user through the Secure Boot configuration in a more
  understandable and simplified way.
- Helps to establish the trusted keys and certificates database.

## Requirements

Requirement use the words defined in
[RFC2119](https://datatracker.ietf.org/doc/html/rfc2119).

### General

<!--
Src: https://github.com/Kicksecure/kicksecure-wiki-backup/blob/6900fdfbdea8693fdf1b72e56bd6e5dcfc1685aa/Verified_Boot.mw#L1163

==== user-controlled verified boot UEFI Application ====
* UEFI compatibility: yes
* CSM ("legacy" BIOS / SeaBIOS): No.
* compatible with non-compliant ("legacy") operating systems: yes (such as Debian 12, Microsoft Windows, as usual)
** EDIT: "legacy" means Microsoft UEFI Signing key only
* Generic concept: yes
* Architecture specific implementation: Yes, initially <code>amd64</code> only.
* Architecture support: Initially <code>amd64</code> only. In principle, can be ported to other architectures by third parties.

-->

1.1. The application MUST be compatible with UEFI 2.7 Specification. Any
     system compliant with the aforementioned specification version SHOULD be
     capable of running this application.

1.2. The application SHALL NOT support systems running in legacy
     BIOS/compatibility mode (CSM).

1.3. The application SHOULD be tested and verified on AMD64 architecture only.
     However, the architecture support MAY NOT be limited to AMD64 only and
     MAY also work on any architecture supported by the UEFI Specification 2.7
     (refer to Section 2.3 Calling Conventions).

<!--
* Vendor neutral: yes, any operating system that wishes to be compatible with the "EFI_ALT" standard/convention is welcome to.
* Kicksecure specific: no
* Kicksecure branding: no
-->

1.4. The application MUST be OS/HW vendor agnostic and NOT subject to any
     branding.

### Keys and boot options management

<!--
* Boot compatibility with mainstream operating systems such as Microsoft Windows: Yes, the user-controlled verified boot feature should not restrict the user's freedom to boot any operating system, if they so confirm in their firmware. (This is useful to avoid "Linux-only motherboard" and to keep resale value higher.)
-->

2.1. The application MUST NOT restrict the ability to boot any UEFI-compliant
     operating system.

<!--
* Support for binaries signed by multiple keys: Yes. (UEFI already supports that.) (This is important to allow the distribution or customer to cycle/replace the key in later upgrades or for planned signing key changes.)
-->

2.2. The application MUST support images singed by multiple keys.

<!--
* Public key TOFU (trust on first use): yes, if confirmed in the firmware.
-->

2.3. The application MUST ask the user for confirmation to trust given key
     on the first use. The application MAY maintain the base of trusted keys
     separately from UEFI Secure Boot or use existing UEFI Secure Boot
     databases.

<!--
* Show key fingerprint: yes - "key fingerprint [key fingerprint]" [info symbol] "What is this? Brief explanation that the user can check with the vendor of this operating system if they wish to trust that key."
-->

2.4. The application SHOULD present the information about keys and
     certificates in human-readable form using Issuer's and Subject's Common
     Name (CN) and Organization (O) or other fields if present. Additionally,
     the key fingerprint MUST always be displayed.

<!--
* Microsoft Secure Boot default signing key:
** included in the firmware by default: yes, required for the purpose of allowing the user to boot Microsoft Windows
** trusted in the firmware by default: no, express permission by the user is needed. (Because this key could lead to Secure Booting a Linux malware distribution. This would be unwanted by users who wish to use full verified boot with their chosen key.)
* What this is:
** A mechanism for users to much more easily choose which keys they trust.
-->

2.5. The firmware SHOULD include the Microsoft UEFI Secure Boot keys and
     certificates in the firmware vendor's default set of UEFI Secure Boot
     keys.

2.6. The firmware vendor's default UEFI Secure Boot key and certificate set
     SHALL NOT be trusted by default, unless explicitly confirmed by the user.
     The application SHOULD assist in configuring the default keys and
     certificates.

<!--
* What this is:
** A mechanism for users to much more easily choose which keys they trust.
-->

2.7. The application SHOULD assist in trusted key/certificate set selection.

<!--
** If verification fails, load firmware-internal database of well-known keys that the user may or may not trust
** Check boot medium for public key database in a well-known location; if it exists, load keys from it and add any new keys not already present in firmware to the list of possibly usable keys (but do not trust any key ever without user confirmation)
-->

2.8. The application SHALL scan EFI System Partition (ESP) for available keys
     and certificates. The certificates MUST be X509 DER encoded. The
     application MAY save the list of found and usable keys and certificates
     in a separate UEFI variable for future use.

<!--
** Power on -> find list of candidate bootloaders (or let user choose bootloader to load via boot menu, as usual)

* Additional notes:
** To handle the situation where multiple shims are installed, the firmware may need the ability to find multiple candidate bootloaders in the removable media path (or any bootloader path)
-->

2.9. The application SHALL scan EFI System Partition (ESP) for operating
     system bootloaders.

<!--
* alternative bootloader (such as shim) in alternative location: yes
** <code>/EFI_ALT/BOOT/BOOTX64.EFI</code> (TBD)
* Secure boot public key by Linux distribution or customer in a well-known location: yes
* Secure boot public key database well-known location:
** <code>/EFI_ALT/BOOT/key.1.key</code> (TBD)
** <code>/EFI_ALT/BOOT/key.2.key</code> (TBD)
** <code>/EFI_ALT/keydb/keys.db</code> (TBD)
** <code>/EFI_ALT/debian/shimx64.efi</code> (TBD)
** <code>/EFI_ALT/debian/shimx64.1.key</code> (TBD)
** <code>/EFI_ALT/debian/shimx64.2.key</code> (TBD)
** <code>/EFI_ALT/debian/key.1.key</code> (TBD)
** <code>/EFI_ALT/debian/key.2.key</code> (TBD)
** <code>/EFI_ALT/KEYDB/BOOTX64.1.KEY</code> (TBD)
** <code>/EFI_ALT/KEYDB/BOOTX64.2.KEY</code>(TBD)
*** EDIT: Whether we stick with EFI_ALT or any fixed directory structure or let the application locate all possible keys and bootloaders is still under discussion.
-->

2.10. The keys, certificates and bootloaders MAY be stored in different
      location on ESP than the default location specified by the operating
      system.

<!--
** If verification fails, load firmware-internal database of well-known keys that the user may or may not trust
** Check boot medium for public key database in a well-known location; if it exists, load keys from it and add any new keys not already present in firmware to the list of possibly usable keys (but do not trust any key ever without user confirmation)
** Check to see if any of the keys can verify the image
*** A) <u>If no,</u> boot fails, continue to the next bootloader in the list
*** B) <u>If yes,</u> prompt user if they want to trust the key
**** Display the path to the bootloader image that the firmware is currently verifying
**** Display whether the key was found in the firmware-internal database or in a database provided by the boot medium
**** Display key fingerprint so the user can verify it themselves if they so desire
**** If the user chooses not to trust the key, boot fails, continue to the next bootloader in the list
**** If the user chooses to trust the key, key is enrolled into trusted Secure Boot database and boot continues
-->

2.11. The application SHALL verify the signatures of each bootloader located
      on ESP and match it with a key/certificate located either on the ESP or
      the default certificate set. The application MUST display the bootloader
      path, key information and verification result.

2.12. The application SHALL ask the user to trust the key used to sign each
      bootloader, if the key has been found in either ESP or firmware default
      key set and the image passes the verification.

2.13. The application MAY offer to create a persistent boot option for a
      bootloader signed with a trusted key.

### Integration

<!--
* Must be a motherboard deemed commercially profitable by the OEM: yes.
* Must be a feature that the firmware developer considers potentially commercially beneficial (as in customers would buy motherboards with such freedom-preserving firmware): yes
-->

3.1. The application is RECOMMENDED be integrated into the system's firmware
     image.

3.2. The application MAY be launched from a predefined location on EFI System
     Partition (ESP).

3.3. The application MUST be run on the very first power on of the system and
     on every `EFI_BOOT_MODE` set to `BOOT_WITH_DEFAULT_SETTINGS` or
     `BOOT_WITH_MFG_MODE_SETTINGS` per UEFI Platform Initialization
     Specification.

<!--
* Technical high-level overview:
** Power on -> find list of candidate bootloaders (or let user choose bootloader to load via boot menu, as usual)
** Loop through the list trying to verify and boot each one
** Verify bootloader signature against in-firmware trusted Secure Boot database
** If verification passes, continue boot
** EDIT: If verification fails, pass control to the application
-->

3.4. The firmware MAY run the application if the bootloader image verification
     fails and the firmware is unable to boot the operating system.

<!--
There will be no enforcement of image verification if permissive policies or
bugs like MSI inSecure Boot will be present in the firmware.
-->

3.5. The firmware SHOULD NOT implement insecure image verification policies
     allowing to bypass signature verification when UEFI Secure Boot is
     enabled.

## Usecase examples

<!--
* Technical high-level examples:
** Power on -> firmware detects Microsoft Windows (bootloader) is installed -> show the key to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** Power on -> firmware detects a "standard" Linux distribution such as Debian without a key in the well-known location -> show default Microsoft signing key for shim to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** Power on -> firmware detects an "augmented" Linux distribution such as Kicksecure with a key database in the well-known location -> show key from key database to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** User disables Secure Boot -> as usual
-->

-->

### Initial configuration

<!-- TODO: diagrams? -->

1. User powers on the platform.
2. Firmware performs boot media enumeration.
3. Firmware detects initial boot or boot with default settings and launches an
   application.
4. The application visits all handles with `gEfiSimpleFileSystemProtocolGuid`
   and `gEfiPartTypeSystemPartGuid`.
5. For each handle, find operating system bootloader. E.g. GRUB, SHIM, Windows
   Boot Manager.
6. For each handle, search for files containing keys and certificates. E.g.
   files with `.der`, `.cer`, `.key` extensions.
7. For each bootloader found in step 5, match a key found in step 6 or
   `PKDefault`, `KEKDefault`, `dbDefault`, `dbxDefault`.
8. If key not in `dbxDefault`, attempt image verification and report the
   result to the user.
9. If verification passed, ask the user to trust the key and optionally offer
   to add a boot option.
11. If the user decides to trust the key, the key is added to `DB`.
12. Ask the user to continue boot or proceed with next bootloader verification
    (go to step 8).
13. If the user decided to continue boot, ask the user to enroll a `PK` from a
    pool of detected keys. Then enable Secure Boot and proceed with booting.
14. If no more bootloaders present and user did not trust any key, go to the
    firmware setup menu.

### Secure Boot fails to verify the image

1. User powers on the platform.
2. Firmware performs boot media enumeration.
3. Firmware attempts to boot a boot option according to boot order.
4. Image pointed by the boot option fails the verification.
5. The firmware launches the application to handle possibly new operating
   system or a change in the operating system keys/components.
6. The application scans the partitions for new and untrusted keys.
7. The application verifies if the boot options in the boot order have a
   matching key and pass verification.
8. The application present the key to the user and asks to add a new key to
   the trusted database `DB` if the verification passes.
9. If the user added the key as trusted, continue to boot. Otherwise go back
   to the firmware setup or attempt the next boot option in order.
