# Verified Boot Dasharo

## 1. Introduction

### Trust, chain of trust, root of trust

### Categorization of chains/roots of trust

#### RTM(measurements)

#### RTV(verification)

#### RTR(reporting)

#### RTS(storage)

### The difference between secure boot and measured boot

### Integrity vs authenticity, digest vs signature

## 2. Structure

### Threat model

### Functional requirements

### Non-functional requirements

## 3. Firmware

### Legacy / UEFI / Heads

### Firmware protections against changings settings in its UI

### Firmware protections against

### Intel Boot Guard / AMD Platform Secure Boot

## 4. OS-level approaches at limiting system modification

* 836-849: "Other Distributions implementing Verified Boot"
* 864-867: "Forum Discussion"
* 915-937: "Part 2: Firmware and OS" - also linked in `### 3. Firmare`
  as it touches both topics

### Role-based boot modes

* 574-582: "Verified Boot for User but not for Admin" - also
  linked in `### dm-verity` as it mentions it

### Read-only/discardable-file-systems

* 291-295: "Qubes Specific" - /usr reset on reboot
* 301-400: "Verified Boot Discussion" - approaches to
  immutability
* 851-862:"Immutable Linux Distributions"

### Checksum verification

* 509-544: "Hash Check all Files at Boot"
* 343-354: "Mutability in Verified Boot Systems" - related, it was suggested to
  move the section here entirely. Also linked in `###Read-only/discardable-file-systems`

### dm-verity

* 546-: "dm-verity - system versus user partition"
* 574-582: "Verified Boot for User but not for Admin" - mentions dm-verity, also
  linked in `### Role-based boot modes`

### ISOs

* 401-440: "Kicksecure ISO and Verified Boot", "Challenges with Key Management with Secure Boot"

### VMs

* 472-507: "{{project_name_short}} Verified Boot Development Ideas" - Not sure
  if it fits here. Should the section rather talk about QubesOS?
* 509-544: "Hash Check all Files at Boot" - also linked in
  `### Checksum verification`, but it says that "This concept applies only to
  virtual machines"
* 939-945: "Part 3: OS and VMs"
