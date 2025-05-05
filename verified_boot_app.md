# User-controlled Verified Boot UEFI Application

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
* Must be a motherboard deemed commercially profitable by the OEM: yes.
* Must be a feature that the firmware developer considers potentially commercially beneficial (as in customers would buy motherboards with such freedom-preserving firmware): yes
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
* Support for binaries signed by multiple keys: Yes. (UEFI already supports that.) (This is important to allow the distribution or customer to cycle/replace the key in later upgrades or for planned signing key changes.)
* Public key TOFU (trust on first use): yes, if confirmed in the firmware.
* Show key fingerprint: yes - "key fingerprint [key fingerprint]" [info symbol] "What is this? Brief explanation that the user can check with the vendor of this operating system if they wish to trust that key."
* Kicksecure specific: no
* Kicksecure branding: no
* Vendor neutral: yes, any operating system that wishes to be compatible with the "EFI_ALT" standard/convention is welcome to.
* Boot compatibility with mainstream operating systems such as Microsoft Windows: Yes, the user-controlled verified boot feature should not restrict the user's freedom to boot any operating system, if they so confirm in their firmware. (This is useful to avoid "Linux-only motherboard" and to keep resale value higher.)
* AMD OpenSIL: optional, yes. Not a strong requirement for the first iteration. Might be developed later.
** EDIT: Not related. 
* Microsoft Secure Boot default signing key:
** included in the firmware by default: yes, required for the purpose of allowing the user to boot Microsoft Windows
** trusted in the firmware by default: no, express permission by the user is needed. (Because this key could lead to Secure Booting a Linux malware distribution. This would be unwanted by users who wish to use full verified boot with their chosen key.)
* What this is:
** A mechanism for users to much more easily choose which keys they trust.
* Technical high-level overview:
** Power on -> find list of candidate bootloaders (or let user choose bootloader to load via boot menu, as usual)
** Loop through the list trying to verify and boot each one
** Verify bootloader signature against in-firmware trusted Secure Boot database
** If verification passes, continue boot
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
* Technical high-level examples:
** Power on -> firmware detects Microsoft Windows (bootloader) is installed -> show the key to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** Power on -> firmware detects a "standard" Linux distribution such as Debian without a key in the well-known location -> show default Microsoft signing key for shim to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** Power on -> firmware detects an "augmented" Linux distribution such as Kicksecure with a key database in the well-known location -> show key from key database to the user -> user confirms or denies the key -> continue boot (if confirmed, otherwise go back to firmware menu or something)
** User disables Secure Boot -> as usual
* Additional notes:
** To handle the situation where multiple shims are installed, the firmware may need the ability to find multiple candidate bootloaders in the removable media path (or any bootloader path)

-->
