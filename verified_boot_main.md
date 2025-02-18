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

### Role-based boot modes

### Read-only/discardable-file-systems

### Checksum verification

### dm-verity

### ISOs

### VMs