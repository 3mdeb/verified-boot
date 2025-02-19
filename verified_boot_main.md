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

* 915-937: "Part 2: Firmware and OS" - also linked in `### 4. OS...`
  as it touches both topics

### Legacy / UEFI / Heads

* 417-440: "Challenges with Key Management with Secure Boot" - about EFI
* 766: "Hardware Keystore - HSM" - empty section, maybe worth filling

### Firmware protections against changing settings in it's UI

### Firmware protections against changing firmare's flash chip

*  811-830: "Write Protection"

### Intel Boot Guard / AMD Platform Secure Boot

* 255, 263, 267: "coreboot's Measured Boot, TPM, FlashKeeper" - some
  pros/cons of Boot Guard

## 4. OS-level approaches at limiting system modification

### Role-based boot modes

### Read-only/discardable-file-systems

### Checksum verification

### dm-verity

### ISOs

### VMs