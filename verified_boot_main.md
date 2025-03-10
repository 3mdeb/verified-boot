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

### Read-only

Read-only is a file-system permission, allowing for reading and copying the
data, but prohibits modification and addons. A file, directory or entire disk
can be subject to `read-only`[^1]. A physical media format plays significant
role to `read-only` attribute. Some storage media like CD-Rs, DVDs or ROMs
become read-only storage medium once initial data has been written. Other
mediums like SD-cards, might have physical switch which sets the medium to read-only mode[^2].

A read-only file system is a type of filesystem that prohibits altering data to
ensure integrity and stability of the files. The primary purposes for read-only filesystems are: prohibiting unauthorized or accidental modifications, improving
system reliability and enhancing security[^3].

Some filesystems are inherently read-only by design, examples are:
* ISO 9660 - industry standard, read-only media format designed for
compact-disk read-only memory (CD-ROM)[^4].
* SquashFS - compressed, read-only filesystem for archival use on Linux. Intended for scenarios where low overhead is needed[^5].
* EROFS - stands for "Enchanced Read-Only File System", a general-purpose,
flexible filesystem focused on runtime-performance[^6].

Linux kernel provides and abstraction layer called VFS, which allows for read-only access for non-read-only filesystems[^7].

#### References

[^1]: [read-only](https://www.computerhope.com/jargon/r/readonly.htm)
[^2]: [read-only](https://techterms.com/definition/read-only)
[^3]: [read-only-file-system](https://www.sliksafe.com/blog/read-only-file-system)
[^4]: [iso-9660](https://www.ibm.com/docs/en/i/7.5?topic=formats-iso-9660)
[^5]: [squashfs-4.0-filesystem](https://docs.kernel.org/filesystems/squashfs.html)
[^6]: [erofs-enhanced-read-only-file-system](https://docs.kernel.org/filesystems/squashfs.html)
[^7]: [mount-linux-manual-page](https://man7.org/linux/man-pages/man8/mount.8.html)

### Checksum verification

### dm-verity

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
