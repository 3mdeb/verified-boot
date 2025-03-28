# Threat Model

## User group definition

**Security-Conscious Technical Professionals**

[Persona overview](threat-model-persona.md)

## Threat model

| **What I want to protect?** | **Who I am protecting it from?** | **How likely protection is required?** | **Impact of an adversary breach?** | **Effort exerted on improved security?** |
| --- | --- | --- | --- | --- |
| **Cryptographic Keys** | Remote adversaries, malware seeking identity theft or key compromise | High – frequently targeted due to high value and access. | Critical – identity and authentication compromise risk. | High – significant secure storage, key management investment. |
| **Sensitive Open-Source Code** | Tampering, backdooring, sabotage | Medium-High – attractive due to potential wide-reaching impact. | Critical – broad and severe impact possible if compromised. | High – robust signing, reproducible builds, software bill of materials, audits required. |
| **Build Systems & Supply Chain** | Supply-chain attackers, compromised external software providers | Medium-High – increasingly common and sophisticated. | Critical – compromised builds lead to cascading vulnerabilities. | High – strong signing, reproducible builds, software bill of materials, robust audits required. |
| **Hardware Integrity** | Supply-chain attacks, physical tampering | Medium – sophisticated, less frequent attacks. | Critical – fundamental to system integrity and security. | High – substantial supply-chain validation, hardware audits essential. |
| **Web of Trust & Identity Verification** | Malicious actors, impersonators, compromised keys | Medium – targeted for fraud, impersonation, and infiltration. | Critical – undermines trust and authenticity across the ecosystem. | High – rigorous identity verification, cryptographic proof required. |
| **VPN and Network Integrity** | Remote attackers, MITM attacks | Medium-High – desirable entry-point for adversaries. | High – could lead to significant further compromises. | High – robust cryptographic protocols, TPM attestation needed, network configuration, firewalling, VLAN, Intrusion Detection System. |
| **Research Data** | Competitors, targeted cyber-attacks for intellectual property, corporate espionage | Medium – targeted selectively for competitive advantage. | High – severe reputational and financial impact if leaked. | Medium-High – encryption, secure VM environments required, backups. |
| **SME Business Data** | Competitors, ransomware, insider threats | Medium – common targets motivated by financial gain. | High – considerable financial and operational disruption. | Medium – practical with regular backups, encryption, monitoring. |
| **Personal and Family Data** | Cybercriminals, identity theft, harassment | Medium – commonly targeted but typically less sophisticated. | High – significant personal and financial consequences. | Medium – achievable with basic isolation, encryption and privacy practices. |
