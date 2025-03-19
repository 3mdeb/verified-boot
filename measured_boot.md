# Measured Boot

Measured boot is a security mechanism designed to verify that all the firmware
and software executed during the boot process are trusted by measuring them
and documenting the measurements for future validation.

Contrary to verified boot[^VerifiedBoot], measured boot does not prevent
untrusted code from being executed, but it makes it impossible for the execution
of such code to go undetected.

[^VerifiedBoot]: [Verified Boot Page](./verified_boot_main.md)

## Measured Boot and the Trusted Platform Module

The Trusted Platform Module (TPM) is a secure cryptoprocessor, a dedicated
microprocessor seperate from the CPU, able to perform cryptographic operations
in a secure, tamper resistant environment. The TPM was created by the
Trusted Computing Group, which maintains and develops its
specification[^TPM_Spec]. The second edition of the specification is published
as the is the ISO/IEC 11889[^TPM_standard] standard.

The Trusted Platform Module is often used in modern systems in the process of
measured boot as the Root of Trust for Storage and the
Root of Trust for Reporting.

### Root of Trust for Storage

The TPM contains a volatile and non-volatile storage, which are not directly
available to the rest of the system and are guarded by the TPM.
Thanks to these storages, the TPM can be used as the the Root of Trust for
Storage.

#### Platform Configuration Register (PCR)

The PCRs[^TPM_spec_11-6-2] are small secure memory locations in the TPM which
can be read by the system freely, but cannot be directly written to.
A PCR can only be modified by:

- resetting[^TPM_spec_17-1]
- extending[^TPM_spec_17-2]

Extending a PCR is a key operation in the process of measured boot using TPM.
Extending a hash consists of appending some data to the bytes of the hash and
calculating the hash of the resulting bytes sequence.
Every measured boot measurement is recorded by adding it to a measurement log
and performing a hash extension of a value in a PCR and the measured component's
digest. The resulting hash value is then set as the new value of
the PCR by the TPM.

The integrity of the measurement log can be verified by calculating and
extending all the digests in the log. The resulting value can be compared
against the one saved in a PCR as any change to the chain of measured components
will result in a different hash value in the end.

Comparing the values in PCRs to some well-known ones allows to verify the
integrity of all the components measured during the process of measured boot
in one operation.

### Root of Trust for Reporting

The TPM allows to ensure the integrity and authenticity of the data read from
its storage. Because of that it can act as the
Root of Trust for Reporting of the data stored in the TPM's storage.

One way this can be achieved is by creating a HMAC[^NIST_HMAC] session with the
TPM[^TPM_spec_17-7-2]. The PCR value will be provided alongside a HMAC allowing
for verifying that it comes from the TPM chip and was not altered in any way.

### Static and Dynamic RTM

### EK and hierarchies

[^TPM_standard]: https://www.iso.org/standard/66513.html
[^TPM_Spec]: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_11-6-2]: Section 11.6.2, Platform Configuration Registers (PCR), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-1]: Section 17.1, Initializing PCR, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-2]: Section 17.2, Extend of a PCR, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-7-2]: 17.7.2 Authorization Set, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^NIST_HMAC]: NIST FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf

PCRs
Sealing/unsealing operations
Difference between static and dynamic RTM
EK and hierarchies

Short (1-2 sentences max) description of differences between measured and verified boot, with link to verified boot page.