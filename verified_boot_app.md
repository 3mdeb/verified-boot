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

1.1. The application MUST be compatible with UEFI 2.7 Specification. Any
     system compliant with the aforementioned specification version SHOULD be
     capable of running this application.

1.2. The application SHALL NOT support systems running in legacy
     BIOS/compatibility mode (CSM).

1.3. The application SHOULD be tested and verified on AMD64 architecture only.
     However, the architecture support MAY NOT be limited to AMD64 only and
     MAY also work on any architecture supported by the UEFI Specification 2.7
     (refer to Section 2.3 Calling Conventions).

1.4. The application MUST be OS/HW vendor agnostic and NOT subject to any
     branding.

### Keys and boot options management

2.1. The application MUST NOT prevent a user from booting any UEFI-compliant
     operating system. It MAY prompt the user to grant trust to an unknown key
     or to disable UEFI Secure Boot for that boot, but it must always offer at
     least one successful path.

2.2. The application MUST support images singed by multiple keys.

2.3. The application MUST ask the user for confirmation to trust given key
     on the first use. The application MAY maintain the base of trusted keys
     separately from UEFI Secure Boot or use existing UEFI Secure Boot
     databases.

2.4. The application SHOULD present the information about keys and
     certificates in human-readable form using Issuer's and Subject's Common
     Name (CN) and Organization (O) or other fields if present. Additionally,
     the key fingerprint MUST always be displayed.

2.5. The firmware SHOULD include the Microsoft UEFI Secure Boot keys and
     certificates in the firmware vendor's default set of UEFI Secure Boot
     keys.

2.6. The firmware vendor's default UEFI Secure Boot key and certificate set
     SHALL NOT be trusted by default. Trust shall only be given to these keys
     if explicitly confirmed by the user.

2.7. The application SHOULD assist in trusted key/certificate set selection.

2.8. The application SHALL scan EFI System Partition (ESP) for available keys
     and certificates. The certificates MUST be X509 DER encoded. The
     application MAY save the list of found and usable keys and certificates
     in a separate UEFI variable for future use.

2.9. The application SHALL scan EFI System Partition (ESP) for operating
     system bootloaders.

2.10. The keys, certificates and bootloaders MAY be stored in different
      location on ESP than the default location specified by the operating
      system.

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

3.1. The application is RECOMMENDED be integrated into the system's firmware
     image.

3.2. The application MAY be launched from a predefined location on EFI System
     Partition (ESP). The application MUST be signed with a key or possess a hash
     trusted by the firmware if this is done.

3.3. The application MUST be run on the very first power on of the system and
     on every `EFI_BOOT_MODE` set to `BOOT_WITH_DEFAULT_SETTINGS` or
     `BOOT_WITH_MFG_MODE_SETTINGS` per UEFI Platform Initialization
     Specification.

3.4. The firmware MAY run the application if the bootloader image verification
     fails and the firmware is unable to boot the operating system.

3.5. The firmware SHOULD NOT implement insecure image verification policies
     allowing to bypass signature verification when UEFI Secure Boot is
     enabled.

## Usecase examples

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
