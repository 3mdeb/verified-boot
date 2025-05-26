# Verified Boot Provisioning Wizard UEFI Application

## 1. Introduction

This document specifies the behavior and architecture of a UEFI application
designed to guide end users through the provisioning of UEFI Secure Boot.
The objective is to offer a user-controllable mechanism for managing
platform trust relationships and establishing Secure Boot infrastructure,
with a primary focus on transparency, informed consent, and usability.

Unlike traditional firmware interfaces, which expose Secure Boot as a
collection of loosely connected toggleable settings and unmanaged
certificate stores, this application presents a coherent, wizard-like
experience. Its purpose is to make the process of reviewing and enrolling
platform keys intuitive for users who are not security experts.

## 2. Application Design Overview

On first launch (i.e., when no Platform Key (`PK`) is enrolled and), the
application checks if Secure Boot is enabled (i.e., when Platform Key (`PK`)
is enrolled), if yes, it attempts to delete the PK using platform-specific
method as defined in UEFI Specification. Not enrolled `PK` is the prerequisite
to modify Secure Boot variables and establish user-controlled trust
relationships with the firmware. Then the application begins the scanning and
discovery process. It performs key discovery, bootloader verification, and
presents the user with a sequence of trust decisions.

The Verified Boot Provisioning Wizard is a standalone UEFI application
executed either from a system firmware image. It operates in the pre-boot UEFI
environment, executing under `EFI_BOOT_MODE == BOOT_WITH_DEFAULT_SETTINGS` or
`BOOT_WITH_MFG_MODE_SETTINGS`, or as a fallback mechanism when Secure Boot
verification fails.

Upon launch, the application initializes required protocols and services,
including but not limited to:

* `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` for accessing ESPs
* `EFI_LOADED_IMAGE_PROTOCOL` for self-inspection
* `EFI_VARIABLE_SERVICES_PROTOCOL` for interaction with Secure Boot variables
  and boot option configuration
* `EFI_SECURITY_ARCH_PROTOCOL`/`EFI_SECURITY2_ARCH_PROTOCOL` for verifying
  images via `EFI_BOOT_SERVICES.LoadImage()`

The application executes in several stages, forming a wizard workflow. These
stages include environment scanning, key discovery, signature validation,
and key enrollment.

![](images/app_flow.png)

Only after the Secure Boot environment is provisioned and a Platform Key is
set does the application default to the interactive menu interface on
subsequent invocations. This ensures a streamlined initial experience
focused on system provisioning, while providing full transparency and
control afterward.

## 3. Operational Phases

### 3.1 Environment Initialization

The application can only run before `EFI_BOOT_SERVICES.ExitBootServices()` has
been called.

Upon entry, the application uses `EFI_BOOT_SERVICES.LocateHandleBuffer()` with
`ByProtocol` for `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, identifying all connected
ESP-capable volumes. Each volume is queried via `OpenVolume()` to explore file
systems for Secure Boot material and bootloaders.

### 3.2 Key Discovery on Filesystems and Default Variables

In this phase, the application scans all discovered ESPs for files that may
contain usable public keys and certificates. It searches recursively for
files with known cryptographic formats such as `.cer`, `.der`, or `.key`,
using simple heuristics and file extension matching.

Each candidate file is parsed using an internal X.509 ASN.1 parser. For
every successfully decoded certificate or public key, the application
extracts metadata such as:

* Subject Common Name (CN) and Organization (O)
* Issuer CN and O
* Validity period
* Key type and size
* Fingerprint

These keys are collected into a staging list of potential trust
anchors.

### 3.3 Bootloader Identification and Verification

The application will parse the images of the bootloaders to obtain information
about the signatures. The application will additionally validate bootloaders
using `EFI_BOOT_SERVICES.LoadImage()`. Bootloaders that pass signature checks
using are listed for potential trust decisions. For images with unknown but
verifiable keys, the application initiates a trust prompt as described in the
next section.

The information about the bootloader should include:

* The EFI image device path
* Status of image verification
* Signature list used during verification attempts
* Associated certificates/keys

### 3.4 Trust Decision and Key Enrollment

For each unknown signing key discovered during verification, the application
prompts the user with a detailed summary, including:

* Key path
* Certificate subject and issuer fields (if available)
* Key fingerprint (SHA-256)
* Origin (ESP, firmware default, audit log)

With explicit user consent, the application enrolls the key into the `db`
database using `SetVariable()`. Since the application operates in either
Audit Mode or Setup Mode, authenticated write access is not required.

Only the `db` (permitted image signers) may be updated during this phase.
The `KEK` is not modified unless the user explicitly chooses to enroll
Microsoft's default keys. No changes to `PK` are performed until the end
of the provisioning workflow. This restriction ensures that the platform's
trust anchors and ownership state are not altered prematurely.

At the end of the provisioning workflow, if no Platform Key (`PK`) is
present, the user is prompted to select a key for initial ownership. This
key may be one of the previously trusted certificates or a new key
supplied specifically for the purpose of establishing platform ownership.
The application then sets the `PK` using authenticated variable services and
enables Secure Boot by setting `SetupMode = 0` and `SecureBootEnable = 1`, as
specified in the UEFI Specification.

### 3.5 Boot Option Registration

Once a bootloader is validated and its key is trusted, the application may
offer to register a persistent boot entry by creating UEFI boot variables
directly using the Runtime Services `SetVariable()` interface.

Each boot entry is constructed by writing a `Boot####` variable with the
attributes:

* `EFI_VARIABLE_NON_VOLATILE`
* `EFI_VARIABLE_BOOTSERVICE_ACCESS`
* `EFI_VARIABLE_RUNTIME_ACCESS`

The variable data includes the device path to the bootloader, a human-readable
description (e.g., "Verified Linux Boot"), and optional load options.

The application may also update the `BootOrder` variable to ensure the new
entry is prioritized appropriately.

Registered entries ensure consistent boot behavior after provisioning is
completed.

## 4. Security Model

The application adheres to the security model defined in the UEFI Secure
Boot architecture. It ensures that:

* No key is trusted without explicit user action.
* Bootloaders are not executed unless validated against an enrolled key and
  authorized by the user.
* Keys recorded in audit logs are never enrolled without human review.

## 5. Integration Considerations

This application is a standard UEFI application and must be deployed as an
executable PE32+ image conforming to the UEFI application format. It may
reside on the EFI System Partition (ESP) and be invoked by the firmware
through a boot option, removable media path, or manually through the boot
manager UI.

The application is not a DXE driver, but may be integrated into the firmware
volume to ensure it is always available (recommended).

Firmware implementations are encouraged to invoke the wizard:

* On first boot
* When `EFI_BOOT_MODE == BOOT_WITH_DEFAULT_SETTINGS`
* When Secure Boot verification fails of the previosuly trusted bootloader
* By Boot Manager when none of the boot options work

## 6. User Interface Design

### 6.1 Main Menu

```
+------------------------------------------------------------+
|   Verified Boot Provisioning Wizard                       |
+------------------------------------------------------------+
| > Trusted Key Database                                     |
| > Discovered Keys and Certificates                         |
| > Bootloaders and Verification Status                      |
| > Platform Key Enrollment                                  |
| > View Current Boot Options                                |
| > Exit and Reboot                                          |
+------------------------------------------------------------+
```

Selecting a key from the list opens a detail view:

```
+------------------------------------------------------------+
|   Key Details                                              |
+------------------------------------------------------------+
| Subject: CN=Vendor OS Cert, O=Vendor Inc.                  |
| Issuer:  CN=Vendor Root CA, O=Vendor Inc.                  |
| Fingerprint: SHA256:AB34EF...                             |
| Source: db                                                 |
+------------------------------------------------------------+
|   This key is currently trusted.                           |
|                                                            |
| [Untrust This Key]                                         |
+------------------------------------------------------------+
```

### 6.2 Trusted Key Database

```
+------------------------------------------------------------+
|   Trusted Key Database                                     |
+------------------------------------------------------------+
| > Key 1: CN=Vendor OS Cert, SHA256:AB34... (from db)       |
| > Key 2: CN=Custom Loader, SHA256:9F12... (from user)      |
+------------------------------------------------------------+
```

Selecting a key from the list opens a detail view:

```
+------------------------------------------------------------+
|   Key Details                                              |
+------------------------------------------------------------+
| Subject: CN=Vendor OS Cert, O=Vendor Inc.                  |
| Issuer:  CN=Vendor Root CA, O=Vendor Inc.                  |
| Fingerprint: SHA256:AB34EF...                             |
| Source: db                                                 |
+------------------------------------------------------------+
|   This key is currently trusted.                           |
|                                                            |
| [Untrust This Key]                                         |
+------------------------------------------------------------+
```

### 6.3 Discovered Keys and Certificates

```
+------------------------------------------------------------+
|   Discovered Keys and Certificates                         |
+------------------------------------------------------------+
| > Key 3: CN=OEM Cert, SHA256:D6E7... (from dbDefault)      |
| > Key 4: CN=shim Loader, SHA256:1ACD... (from ESP)         |
+------------------------------------------------------------+
```

Selecting a key opens a detailed trust prompt:

```
+------------------------------------------------------------+
|   Key Details                                              |
+------------------------------------------------------------+
| Subject: CN=shim Loader, O=Linux Foundation                |
| Issuer:  CN=Microsoft UEFI CA                              |
| Fingerprint: SHA256:1ACD34...                              |
| Source: SATA SSD #1 ESP, /EFI/keys/shim.cer                |
+------------------------------------------------------------+
|   This key is not currently trusted.                       |
|                                                            |
| [Trust This Key]                                           |
+------------------------------------------------------------+
```

### 6.4 Bootloaders and Verification Status

```
+------------------------------------------------------------+
|   Bootloaders and Verification Status                      |
+------------------------------------------------------------+
| > SATA SSD #1 ESP: /EFI/ubuntu/grubx64.efi                 |
|     Verified (Key 4)                                       |
| > NVMe0n1p1: /EFI/Microsoft/Boot/bootmgfw.efi              |
|     Failed                                                 |
| > SATA SSD #1 ESP: /EFI/boot/bootx64.efi                   |
|     Verified (Key 3)                                       |
+------------------------------------------------------------+
```

Selecting a bootloader opens a detailed view:

```
+------------------------------------------------------------+
|   Bootloader Details                                       |
+------------------------------------------------------------+
| Path: /EFI/ubuntu/grubx64.efi                              |
| Location: SATA SSD #1 ESP                                  |
| Signature: Verified                                        |
| Signed by: CN=shim Loader, SHA256:1ACD...                  |
+------------------------------------------------------------+
| [Create Boot Entry]                                        |
+------------------------------------------------------------+
```

### 6.5 Current Boot Options

```
+------------------------------------------------------------+
|   Current Boot Options                                     |
+------------------------------------------------------------+
| Boot0000: SATA SSD #1 ESP - Verified Linux Boot            |
| Boot0001: NVMe0n1p1 - Windows Boot Manager                 |
| Boot0002: USB Drive Partition 1 - Recovery Utility         |
+------------------------------------------------------------+
```

### 6.6 Platform Key Enrollment

```
+------------------------------------------------------------+
|   Platform Key Enrollment                                  |
+------------------------------------------------------------+
| [ ] Use existing trusted key (Key 1)                       |
| [ ] Use OEM default key (PKDefault)                        |
| [ ] Load external key from ESP                             |
|                                                            |
| [Enroll Platform Key and Enable Secure Boot]               |
+------------------------------------------------------------+
```

### 6.7 Device Name Resolution

To render human-readable disk and partition identifiers, the application
extracts metadata using UEFI protocols. During device enumeration, the
application:

1. Uses `EFI_DEVICE_PATH_PROTOCOL` to resolve device paths for bootloaders
   and certificates.

2. Uses `EFI_BLOCK_IO_PROTOCOL` to obtain disk metadata such as:

   * Partition number
   * Media label or GUID (if available)
   * Removability status

3. Derives friendly names from device path nodes:

   * For NVMe devices: extract namespace ID and format as `NVMe0n1` or similar
   * For SATA/ATA: match controller and port, e.g., `SATA SSD #1`
   * For USB: format as `USB Drive` or append device serial if known

The application combines this data to generate labels like:

* `Samsung SSD 980 1TB Partition 1`
* `eMMc Device Partition 1`
* `USB SanDisk 3.2Gen1 Partition 1`

These identifiers are shown consistently throughout the UI in bootloader
and certificate listings, helping users make more informed trust decisions. in bootloader
and certificate listings, helping users make more informed trust decisions.

## 7. Compliance and Compatibility

The Verified Boot Provisioning Wizard complies with:

* [UEFI Specification 2.7](https://uefi.org/specifications)
* Section 32: Secure Boot and Authenticated Variables
* Section 3: Boot Services
* Section 2.3: Calling Conventions (for architecture compliance)
* Platform Initialization (PI) Specification regarding `EFI_BOOT_MODE`

The application is initially validated for `amd64` platforms, but the design
is portable across all UEFI-defined architectures.

## 8. Security Considerations

Not every combination of components in the boot chain may provide secure
solution maintaining the chain of trust. Example flows for the most popular
Linux distributions booting methods have been shown below with possible risks.

1. Booting GRUB:

  GRUB may break the chain of trust being unable to verify initrd. The Linux
  kernel has to enabled EFI stub. Passing command line parameters is
  questionable without UKI.

  ![](images/booting_grub.png)

2. Booting Shim:

  Shim introduces another trust anchor and implicitly adds distro key to its
  own trusted key database. As it breaks the principle of not trusting any key
  without user's consent, considering the shim inside the application should
  be prohibited. However, the chain of trust is maintained by GRUB using shim
  protocol.

  ![](images/booting_shim.png)

3. Booting systemd-boot:

  Situation is similar as with GRUB. The systemd-boot bootloader must be
  signed with a distro key, as well as the kernel with enabled EFI-stub.
  Passing command line parameters is questionable without UKI.

  ![](images/booting_systemd_boot.png)

1. Booting Linux kernel directly

  UEFI can boot the Linux kernel directly, if the kernel is built with EFI
  stub. However, the boot options needs to specify the command line parameters
  inside the boot option's additional data. That approach requires special
  support on the firmware side and is also questionable with regards to
  command line parameters passing. Unless the UKI is used.

  ![](images/booting_linux.png)

---

*End of Specification.*
