# Security Policy

## 🛡️ Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported | Status |
| :--- | :---: | :--- |
| **v2.0.x** | ✅ | **Active Development (Latest)** |
| < v2.0.0 | ❌ | End of Life |

---

## 🔒 Reporting a Vulnerability

The KotSafe Security Team takes all security vulnerabilities, cryptographic flaws, and packet engine boundary issues seriously. We appreciate responsible disclosure from security researchers and the open-source community.

### How to Report:
* **Option 1 (Private GitHub Advisory)**: Please use GitHub's private vulnerability reporting feature by navigating to the [Security Advisories tab](https://github.com/SurajAdhikari0/KotSafe/security/advisories) on this repository and clicking **"Report a vulnerability"**.
* **Option 2 (Direct Email)**: If you prefer direct communication or have sensitive exploit details, email the lead maintainer:
  * **Contact**: [Suraj Adhikari](https://github.com/SurajAdhikari0)
  * **Subject Prefix**: `[KotSafe Security Disclosure] - <Brief Description>`

### What to Include:
1. **Description**: Clear description of the vulnerability, affected components, and potential impact.
2. **Reproduction Steps**: Step-by-step instructions or Proof of Concept (PoC) to reproduce the issue.
3. **Environment**: Device model, Android OS version, and KotSafe flavor (`Standard` vs `Full-Power`).
4. **Proposed Fix (Optional)**: Any suggestions or diffs to remediate the vulnerability.

### Our Commitment:
* We acknowledge reports within **48 hours**.
* We work with you to analyze, reproduce, and validate the vulnerability.
* We provide timely patches and credit researchers in the release notes upon public disclosure (unless anonymity is requested).

---

## 🏛️ Security Architecture & Privacy Guarantee

* **100% On-Device Processing**: KotSafe does not transmit user packets, network payloads, or DNS lookups to any cloud telemetry server.
* **Cryptographic Keys**: Ephemeral session keys and TLS CA materials are stored in Android Keystore / protected private storage.
* **Clean-Room Native Engine**: The C++/JNI packet inspection core enforces bounds checking and non-root sandbox confinement.
