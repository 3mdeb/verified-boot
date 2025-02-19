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

* 584-644: "Notes" - might be useful here according to the analysis?

### Threat model

### Functional requirements

* 646-683 : "Firmware and Device Requirements"

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

### Read-only/discardable-file-systems

* 851-862:"Immutable Linux Distributions"

### Checksum verification

### dm-verity

### ISOs

### VMs

* 939-945: "Part 3: OS and VMs"