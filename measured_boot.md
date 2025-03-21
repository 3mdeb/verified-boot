# Measured Boot

Measured boot is a security mechanism designed to provide a cryptographic
footprint of the firmware and software executed during the boot process
for future validation and attestation.

Contrary to verified boot[^VerifiedBoot], measured boot does not prevent
untrusted code from being executed, but it makes it impossible for the execution
of such code to go undetected.

Every single piece of code executed since the start-up to the end of the
measured boot process has its digest calculated. The digests, called
measurements, are then stored for future reference using the Root of Trust
for Storage (RTS). The Root of Trust for Reporting (RTR) allows to reliably analyze the
measurements history stored in the RTS and make decisions on the trust towards
the platform depending on whether the sequence of code executed up to a point
is expected, or if a security breach could have happened.

This page will focus on the practical realization of measured boot
using a TPM module. Some more theory regarding the process and the definitions
of basic concepts can be found on the [Verified Boot Page](./verified_boot_main.md)

[^VerifiedBoot]: [Verified Boot Page](./verified_boot_main.md)

## Measured Boot and the Trusted Platform Module

The Trusted Platform Module (TPM) is a secure cryptoprocessor, a dedicated
microprocessor separate from the CPU, able to perform cryptographic operations
in a secure, tamper resistant environment. The TPM was created by the
Trusted Computing Group, which maintains and develops its
specification[^TPM_Spec]. The second edition of the specification is published
as the ISO/IEC 11889[^TPM_standard] standard.

The Trusted Platform Module is often used in modern systems in the process of
measured boot as the Root of Trust for Storage and the
Root of Trust for Reporting.

### Root of Trust for Storage

The TPM contains a volatile (RAM) and non-volatile (NVRAM) storages, which
are not directly available to the rest of the system and the access to them is
controlled by the TPM. Such storage locations protected by the TPM are called
`Shielded Locations`[^TPM_spec_4-89].

Thanks to the protections provided by the TPM it can be used as the Root of
Trust for Storage[^TPM_spec_9-4-3] to document the measured boot measurements,
and protect them from being altered.

The protections and authorization scheme are defined separately for every
data (Object) stored in Shielded Locations.
Three main types of authorization are defined by the TPM specification:
- password,
- HMAC,
- policies.

#### Password Authorization

Password authorization [^TPM_spec_19-4] is the least secure way of authorizing the access to an
object stored in a shielded location. The password is sent between the CPU and
the TPM in plaintext. This authorization scheme should only be
used if using an HMAC is not possible, the channel between the entity seeking
authorization and the TPM is trusted to be secure, or the password is well
known.

#### HMAC Session Authorization

The keyed-Hash Message Authentication Code (HMAC)[^NIST_HMAC] is a code
that allows for verifying both the integrity of a message (like a classical MAC),
but can also be used to verify the authenticity of the source of the message
by mixing a shared secret into the authentication codes.

The secret has to be exchanged by the two communicating parties. It has to be
remembered by the two parties for the duration of the communication,
thus making this authorization scheme `session-based` [^TPM_spec_19-5].

When using the HMAC session for authorization, the shared secret contains the
`authValue` of an entity, which is chosen when creating
the object and required to access it in the future. How exactly it is used to
create the key depends on the usage[^TPM_spec_19-6-11].

#### Authorization Policies

The TPM provides a capability policies for accessing an object[^TPM_spec_19-7-1]. Policies can
be depicted as logic statements and are
composed of three elements:
- policy assertions - statements that can be either true or false,
- OR operators,
- AND operators,

For the access to an object to be granted, the whole logic statement composed
of assertions and AND/OR operators has to be true.
The policy assertions can be freely composed using OR and AND operators to
define arbitrarily complex policies. The policy assertions include, but are
not limited to:
- TPM2_PolicyPassword - plaintext password verification,
  just like the password authorization scheme;
- TPM2_PolicyAuthValue - HMAC session authorization,
  just like the HMAC session authorization scheme;
- TPM2_PolicyPCR - asserting [PCR](#platform-configuration-register-pcr) values.

All the policy assertions specified by the TPM specification can be found in the
section 19.7.7.6 List of Assertions of the TPM specification part 1,
Architecture[^TPM_spec_19-7-7-6].

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

Comparing the values in PCRs to some well-known ones allows verifying the
integrity of all the components measured during the process of measured boot
in one operation.

### Root of Trust for Reporting

The TPM allows ensuring the integrity and authenticity of the data read from
its storage. Because of that it can act as the
Root of Trust for Reporting of the data stored in the TPM's storage.

One way to achieve this is to create a HMAC[^NIST_HMAC] session with the
TPM[^TPM_spec_17-7-2]. The PCR value will be provided alongside a HMAC allowing
for the verification that it comes from the TPM chip and was not altered in any way.

### Not a Root of Trust for Measurements

The TPM can not act as the RTM, because it is not able to initiate the
measurements. The TPM is only a tool which is operated by the CPU[^TPM_spec_34-1].
The TPM can securely store and report its storage, allowing for reliable
recording of the platform state, but the whole process is controlled
by the code running on the CPU.

### Data Sealing and Unsealing

Sealing and unsealing is a functionality of the TPM that allows saving any data
in a Shielded Location [^TPM_spec_4-89] where the access to the data is
controlled by the Autorization Subsystem [^TPM_spec_11-5] where a set of
policies can be used to control the access to the data.

The process of saving the data is called `sealing`. Such data can only be
`unsealed` if the given set of Policies is satisfied.

Sealing an object with an unseal policy so that a set of PCRs has to have
defined values (PolicyPCR) can be used to make sure a secret is only revealed
if the platform is in an expected state, that is no unexpected code was executed
up to a given point. Sealing a piece of data crucial for the boot process,
like the disk password, can prevent the platform from booting and
potentially exposing sensitive data when the platform is not in a trusted
state.

An example of a more complex unseal policy is given in the TPM specification
where a PolicyPCR and a PolicyAuthorize are used together as alternatives
to allow unsealing the secret during a BIOS update. The Update changes the
PCR values making the PolicyPCR fail, but using a signature from the
platform OEM supplying the BIOS update the PolicyAuthorize is satisfied,
and the keys are unsealed by the TPM.[^TPM_spec_19-7-11]

### TPM Key Hierarchies

The TPM is able to generate asymmetric key pairs for specific uses and
act as an authority for attesting the trust towards them. Every key
created using the TPM is a part of some `key hierarchy`.

The key hierarchies are mechanisms of transitive trust, just like the chains
of trust. The trust is transitioned from a `Primary Key` of a hierarchy
down to other keys of the same hierarchy, which in turn can be used to encrypt,
decrypt, sign and verify any data.

The primary keys used to verify the trust towards other keys are not stored
in the non-volatile memory of the TPM, but are instead generated when needed
using the `Primary Seed` of a given key hierarchy.
Generating the Primary Keys is deterministic and will always produce the same key
for a given set of attributes allowing to save space in the TPM's secure NVRAM.
The private parts of Primary Keys never leave the TPM.

The TPM specification defines three `Primary Key Seeds`, and their corresponding
key hierarchies[^TPM_spec_14-4]:
- Endorsement Primary Seed (EPS)
- Storage Primary Seed (SPS)
- Platform Primary Seed (PPS)

The Primary Key Seeds never leave the TPM and are the most important secrets
held by it as all the keys used by the TPM are derived from them.

#### Endorsement Key hierarchy

The Endorsement Key (EK)[^TPM_spec_14-4-2] is the identity of the Root of Trust
for Reporting[^TPM_spec_9-4-4-2]. All the data that is reported by the TPM,
like the PCR values, is authorized to the Endorsement Key.

#### Platform Key hierarchy

A Platform Key (PK)[^TPM_spec_14-4-3] and its hierarchy is controlled by and
used by the platform firmware. The TPM can generate the PK for the
firmware's use, like signing firmware and software components for [verified boot](./verified_boot_main.md).

#### Storage Root Key hierarchy

Storage Root Key (SRK)[^TPM_spec_14-4-4] and the hierarchy of keys signed by
it are controlled by the platform owner. The keys can be used by the OS and
applications for any use, like sealing some secret by encrypting it on the
disk making it only accessible when a policy is satisfied, or for authorization.

## Static and Dynamic RTM

Measured Boot can be performed based on a Static RTM or a Dynamic RTM.
Achieving measured boot using the two Roots of Trust differ in how the process
is performed and each has its strengths and shortcomings. The two techniques can
even be used together to achieve the best results[^Intel_txt_security_paper].

### Static Root of Trust for Measurement (SRTM)

The Static Root of Trust for Measurements (SRTM) creates a Chain of Trust, which
starts with the first code executed on the CPU. The code is often read only,
proprietary and provided by the hardware vendor. From there, every executed
software is being measured and added to the chain of trust extending the
Trusted Computing Base. The process is simple, but the resulting
Trusted Computing Base can end up being large and its security can be difficult
to audit.

### Dynamic Root of Trust for Measurement (DRTM)

The main difference between a Dynamic Root of Trust for Measurement and a Static
Root of Trust for Measurement is that the DRTM does not start with the first
instructions executed on the CPU, but with the execution of a special CPU
instruction (Intel - GETSEC(SENTER)[^Intel_txt_security_paper], or AMD - SKINIT[^AMD_DRTM_guide]). The point where measured boot starts is not static but
controlled by the code, thus its called a Dynamic RTM.

The instruction allows to exclude the boot code, the firmware and the
bootloader, from the TCB by allowing them to run during platform boot, but
ensuring they won't affect the security of the platform after the special
D-RTM CPU instruction is executed. The code executed after the DRTM
initialization instruction is said to run in a measured launch environment
(Intel), or a secure execution environment (AMD).

### Why use SRTM and DRTM at the same time

Modern systems include coprocessors like the Intel ME and AMD ASP, which are
more privileged than any other entity in the system, including the CPU.
Because of that, the environment in which the platform will execute code
after the DRTM initialization instruction can not be entirely hermitized
from them.

For this reason SRTM and DRTM should be used together[^Intel_txt_security_paper_srtm_and_drtm],
so that the highly privileged components like Intel ME and AMD ASP can be
verified using SRTM, and the code running in a measured environment created
using the DRTM, while not entirely hermitized, can at least depend on the
SRTM measurements.

This way the TCB of the SRTM can be reduced to the highly privileged hardware
components that can affect the measured environment of the DRTM, and the TCB
of the DRTM can be left unchanged, and minimal.

### Pros and cons of SRTM and DRTM

|Criterion|SRTM|DRTM|
|--|--|--|
|First measurements|First CPU instructions|Anywhere and anything|
|Size of TCB|Large|Minimal|
|Implementation and use|Simple|Complex|
|Hardware support|Not required|Required|


[^Intel_txt_security_paper]: https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/trusted-execution-technology-security-paper.pdf
[^AMD_DRTM_guide]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/user-guides/58453.pdf
[^Intel_txt_security_paper_srtm_and_drtm]: Intel TXT Security Paper, Details: Establishing a root of
trust with Intel TXT for Servers, paragraph 3. starting with "Intel developed Intel TXT architecture for servers...", https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/

[^TPM_standard]: https://www.iso.org/standard/66513.html
[^TPM_Spec]: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_11-6-2]: Section 11.6.2, Platform Configuration Registers (PCR), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_4-84]: Section 4, definition 84, Sealed Object Data, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_4-89]: Section 4, definition 89, Shielded Location, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_9-4-3]: Section 9.4.3, Root of Trust for Storage (RTS), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_9-4-4-2]: Section 9.4.4.2 Identity of the RTR, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_11-6-3]: Section 11.6.3 Object Store, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_11-5]: Section 11.5 Authorization Subsystem, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_14-4]: Section 14.4, Primary Seed Properties, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_14-4-2]: Section 14.4.2, Endorsement Primary Seed (EPS), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_14-4-3]: Section 14.4.3, Platform Primary Seed (PPS), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_14-4-4]: Section 14.4.4, Storage Primary Seed (SPS), https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-1]: Section 17.1, Initializing PCR, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-2]: Section 17.2, Extend of a PCR, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_17-7-2]: Section 17.7.2 Authorization Set, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-4]: Section 19.4, Password Authorizations, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-5]: Section 19.5, Sessions, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-6-11]: Section 19.6.11, Salted Session Key Generation, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-7-1]: Section 19.7.1, Enhanced Authorization - Introduction, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-7-7-6]: Section 19.7.7.6, List of Assertions, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_19-7-11]: Section 19.7.11 Modification of Policies, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^TPM_spec_34-1]: Section 34.1 Hardware Core Root of Trust Measurement (H-CRTM) Event Sequence, Introduction, https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
[^NIST_HMAC]: NIST FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf