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

### Read-only / immutability

In this chapter, various meanings of "read-only" concept will be explored.

#### Read-only physical media

A read-only, in context of storage media, refers to the property of some
storage medias like ROM chips, CD-ROMs or DVD-ROMs that hold their content
permanently. In theory, a content can be read, but not updated nor removed[^1].

Below are detailed explanations of listed read-only physical media examples:
* ROM chips - ROM (Read-Only Memory) is a non-volatile memory type used in
various electronic devices to store firmware or software that's hardly changed.
Although "read-only" might suggest such memory cannot be altered, there are
various types of ROM memory that can be modified, including[^2]:
    * PROM - programmable read-only memory. A type of ROM memory that allows
    data to be written only once after manufacturing.
    * EPROM and EEPROM - types of Erasable Programmable Read-Only Memory. Both
    memory types can be erased and reprogrammed. For EPROM this is done by
    exposing the chip to ultraviolet light, EEPROM on the other hand can be
    reprogrammed electrically, which makes it suitable for applications where
    data (eg. firmware) must be updated from time to time. Example is BIOS
    chips.
* Optical media - for optical media, a laser beam is used to read and write
data of the medium. Optical mediums, often come in form of disc. Similar to
ROM, the optical mediums can be split into two categories: read-only optical
discs and recordable optical discs[^3]:
    * read-only optical discs - types of optical discs that have data
    permanently written on them, during manufacturing process. Examples are
    CD-ROM (Compact Disc - Read-Only Memory) and DVD-ROMs (Digital Versatile
    Disc - Read-Only Memory).
    * recordable optical discs - allow for recording data with process named
    "burning". These further split into:
        * recordable medias like CD-R and DVD-R where data can burnt until disc
        is full but it cannot be erased;
        * re-writable medias like CD-RW and DVD-RW where data can be burnt and
        erased.

Some of physical medias can have physical toggle switch that makes them
write-protected or read-only, example being SD cards. It should be noted that
SD cards switch works only as suggestion, and can be overwritten in
software[^4].

#### Read-only filesystems

A read-only file system is a type of filesystem that prohibits altering data to
ensure integrity and stability of the files. The primary purposes for read-only
filesystems are: prohibiting unauthorized or accidental modifications,
improving system reliability and enhancing security. Read-only filesystem rely
on file system permissions to restrict write access. An attempt to modify files
would result in permission denied error types[^5].

Some filesystems are inherently read-only by design, examples are:
* ISO 9660 - industry standard, read-only media format designed for
compact-disk read-only memory (CD-ROM)[^6].
* SquashFS - compressed, read-only filesystem for archival use on Linux.
Intended for scenarios where low overhead is needed[^7].
* EROFS - stands for "Enhanced Read-Only File System", a general-purpose,
flexible filesystem focused on runtime-performance[^8].

Note: read-only file systems may not be misconstrued as write-protection, refer
to [read only physical media](#read-only-physical-media) and [ISOs](#isos).

#### Mounting as readonly on Linux

In context of attaching storage devices in Linux, a read-only is a storage
configuration mechanism that ensures no modification can be done to attached
medium, enhancing security and integrity. Mounting a filesystem as read-only
attaches storage with read-only configuration to Linux directory structure.
This configuration acts as a additional layer of protection served by the
system. Linux does allow to mount read-writeable filesystems (eg. ext4) to be
mounted as read-only[^9].

#### Read-only filesystem permission

Read-only is a file-system permission, allowing for reading and copying the
data, but prohibits modification and addons. A file, directory or
[entire disk](#read-only-physical-media) can be `read-only`[^10].

A read-only file is any file with read-only attribute enabled. Such files can
be read but cannot be modified nor removed. A file might be read-only on a file
level or directory level. If I directory read-only permission is set, all the
files in directory inherit that permission[^11]. It is worth noting, that each
filesystem might handle read-only permissions differently, thus "read-only"
should be thought of as a concept, rather than mechanism. For example, NTFS
supports six basic groups of permissions types that include[^12]: read, write,
list folder contents, read & execute, modify and full control.

#### Immutable storage concept

Immutable storage is a term related to "read-only" concept. It is a storage
protocol that ensures stored data cannot be altered within a set of indefinite
amount of time. The term comes from object-oriented programming, which defines
immutable objects as object which state cannot be changed after it's
created. Immutability can be implemented at various levels of storage stacks,
based on both hardware and software solutions[^13].

One of the immutability implementations is WORM (Write Once, Read Many)
principle. On the other hand, a direct implementation of WORM are
[read-only physical media](#read-only-physical-media). WORM principle ensures
once data is written it cannot be altered or removed. Immutability is also
often related to technologies like snapshotting or immutable filesystems[^14].

#### Immutable linux OS

Immutable Linux operating systems are aimed to introduce reliable, more secure
approach to Linux. Immutable Linux OS cores are designed to be unchangeable
and read only, meaning any changes made to the system are lost when system
reboots. The advantages of immutability are:
* increased security - modifications to installed system structure should not
be possible by design,
* easy maintenance - updates are made via atomic upgrades.

These types of systems are updated via creating new OS instance,
deploying it and switching over to the new one. This process is referred to as
"image-based-update"[^15]. Updates are done alongside reboot, the architecture
ensures that in case of failure in updating the system, one can easily revert
system to previous state. There are multiple ways of handling package
installation on immutable distributions. One of the approaches is to
use containerization for applications to ensure they are isolated from core
system[^16]. Some examples of immutable linux distributions are: Fedora CoreOs,
SUSE MicroOS, Fedora Silverblue or NixOS. Each distro has it's own approach and
technology stack that ensure immutability, eg. Fedora OSes and and SUSE MicroOS
use rpm-ostree, which provides read-only access to most of the files[^17].

#### Immutable vs stateless

`Stateless` is a deign principle in which system (not essentially operating
system) or application does not retain any user session information in between
interactions with stateless entity. Each interaction is independent, it
requires full context needed to perform certain action[^18]. Stateless systems
act like they were just were re-deployed from ground up. Such systems never
store any data on persistent storage, instead they rely on receiving
configuration during runtime via various mechanisms[^19]. Immutability and
statelessness should not be confused. Immutability ensures a system cannot be
changed after deployment, statelessness means a system can be entirely replaced
without concern for local state persistence[^20]. The difference between
stateless systems and immutable systems is that stateless system is designed to
be unmodifiable as a whole. Immutable systems on the other hand, ensure that
only core of the system cannot be modified, but some user data is preserved.

[^1]: [read-only](https://encyclopedia2.thefreedictionary.com/read+only)
[^2]: [what-is-rom](https://umatechnology.org/what-is-rom-how-read-only-memory-works-in-computers/)
[^3]: [optical-storage-devices](https://www.igcseict.info/theory/3/optic/index.html)
[^4]: [how-to-fix-sd-card-showing-as-read-only](https://www.stellarinfo.com/blog/sd-card-showing-read-only/)
[^5]: [read-only-file-system](https://www.sliksafe.com/blog/read-only-file-system)
[^6]: [iso-9660](https://www.ibm.com/docs/en/i/7.5?topic=formats-iso-9660)
[^7]: [squashfs-4.0-filesystem](https://docs.kernel.org/filesystems/squashfs.html)
[^8]: [erofs-enhanced-read-only-file-system](https://docs.kernel.org/filesystems/erofs.html)
[^9]: [create-read-only-filesystems-in-linux](https://labex.io/tutorials/linux-create-read-only-filesystems-in-linux-415253)
[^10]: [read-only](https://www.computerhope.com/jargon/r/readonly.htm)
[^11]: [what-is-a-read-only-file](https://www.lifewire.com/what-is-a-read-only-file-2625983)
[^12]: [ntfs-permissions](https://www.permissionsreporter.com/ntfs-permissions)
[^13]: [what-is-immutable-storage](https://www.ibm.com/think/topics/immutable-storage)
[^14]: [immutable-file-systems](https://www.ctera.com/blog/immutable-file-systems-ctera-worm-storage/)
[^14]: [worm-vs.-immutability](https://www.catalogicsoftware.com/blog/worm-vs-immutability-essential-insights-into-data-protection-differences/)
[^15]: [Understanding-immutable-linux-os](https://kairos.io/blog/2023/03/22/understanding-immutable-linux-os-benefits-architecture-and-challenges/)
[^16]: [what-is-immutable-linux](https://www.zdnet.com/article/what-is-immutable-linux-heres-why-youd-run-an-immutable-linux-distro/)
[^17]: [the-future-is-minimal-and-immutable](https://sonalake.com/latest/the-future-is-minimal-and-immutable-a-new-generation-of-operating-systems/) 
[^18]: [stateful-vs-stateless](https://www.ninjaone.com/blog/stateful-vs-stateless-architecture/)
[^19]: [factory-reset-stateless-systems-reproducible-systems-verifiable-systems](https://0pointer.net/blog/projects/stateless.html)
[^20]: [stateless-linux](https://konfou.xyz/posts/stateless-linux/)

### Checksum verification

### dm-verity

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
