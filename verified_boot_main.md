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

* 417-440: "Challenges with Key Management with Secure Boot" - about EFI

### Firmware protections against changing settings in it's UI

### Firmware protections against changing firmare's flash chip

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