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

Device Mapper (DM) is a Linux kernel component for managing logical
volumes[^1]. Device Manager allows mapping physical block devices, to create
virtual block devices[^2].

Device-Mapper's verity (`dm-verity`) provides a read-only target (layer)
providing integrity checking of block devices using kernel crypto API[^3].

`dm-verity` allows for detection if the data has been tampered with at binary
level, a single bit flipped should have impact in hash changing. `dm-verity`
splits block device into blocks and calculates their hashes, which can be
stored on separate (non dm-verity protected) or in unallocated space at the end
of data partition.`dm-verity` follows Merkle tree (hash tree) structure, where
each node (leaf) is labeled with hash of data block. Non-leaf nodes are labeled
with hash of the labels of their child-nodes. Validation proceeds from the
leaves level, up to the root hash, where final validation happens. A simplified
structure is shown on diagram below

```text
                                           Block 8
                                          /
                                Hash H-2-2
                               /          \
                              /            Block 7
                |  Hash H-2  |
                |H-2-1..H-2-2|
               /              \            Block 6
              /                \          /
             /                  Hash H-2-1
            /                             \
           /                               Block 5
|Root hash|
|H-1..H-2 |
           \                               Block 4
            \                             /
             \                  Hash H-1-2
              \                /          \
               \              /            Block 3
                |  Hash H-1  |
                |H-1-1..H-1-2|
                              \            Block 2
                               \          /
                                Hash H-1-1
                                          \
                                           Block 1
```

This structure ensures data integrity as no change can be made without altering
root hash[^4]. In `dm-verity` scheme data is verified as it's being read, any
variations would cause I/O errors[^5].

The `dm-verity` integrity control has disadvantage that limits the storage to
be read-only, which might be challenging to work with in fully-fledge operating
systems. Updates must be performed offline and hashes need to be recalculated.
This works well in embedded environment, where devices are expected to have
identical disk layout[^4].

`dm-verity` is used on Android based devices (since Android 4.4) as a part of
`verified boot`, Google's chain of trust implementation. During boot process,
each stage is being verified prior to executing[^6].

[^1]: [device-mapper-resource-page](https://sourceware.org/dm/)  
[^2]: [dm-verity-rootfs-integrity](https://archive.fosdem.org/2023/schedule/event/image_linux_secureboot_dmverity/attachments/slides/5559/export/events/attachments/image_linux_secureboot_dmverity/slides/5559/DM_Verity.pdf)  
[^3]: [linux-kernel-documentation](https://docs.kernel.org/admin-guide/device-mapper/verity.html)  
[^4]: [dm-verity-in-embedded-device-security](https://www.starlab.io/blog/dm-verity-in-embedded-device-security)  
[^5]: [dm-verity](https://docs.qualcomm.com/bundle/publicresource/topics/80-88500-4/80_DM_verity.html)  
[^6]: [an-introduction-to-dm-verity-on-android](https://technotes.kynetics.com/2018/introduction-to-dm-verity-on-android/)

### ISOs

### VMs
- 939-946    Part 3: OS and VMs
