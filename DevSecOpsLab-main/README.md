# DevSecOps Lab — AI-Powered Auto-Remediation Pipeline

> **Bachelor's Thesis Project** · Information Security  
> An end-to-end DevSecOps platform that automatically **detects, patches, and audits** security vulnerabilities using AI/RAG, Zero Trust secret management, and a tamper-evident audit ledger.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Java](https://img.shields.io/badge/Java-11-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org)
[![LangChain](https://img.shields.io/badge/LangChain-RAG-1C3C3C?style=flat-square&logo=langchain&logoColor=white)](https://langchain.com)
[![SonarQube](https://img.shields.io/badge/SonarQube-SAST-4E9BCD?style=flat-square&logo=sonarqube&logoColor=white)](https://sonarqube.org)
[![Vault](https://img.shields.io/badge/HashiCorp_Vault-ZeroTrust-FFEC6E?style=flat-square&logo=vault&logoColor=black)](https://vaultproject.io)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## What This Project Does

Traditional DevOps pipelines detect security issues but still rely on engineers to fix them manually — a slow, error-prone process that leaves a window for exploitation. This project closes that loop with a fully automated **Detect → Patch → Validate → Audit** cycle:

1. **Developer pushes code** → CI/CD triggers SAST scan (SonarQube)
2. **Vulnerabilities** are ingested into DefectDojo (ASPM)
3. **AI Engine (RAG + Ollama)** retrieves the relevant secure-coding rule from a local vector store (ChromaDB), then generates a targeted patch
4. **3-Gate Validation** compiles, unit-tests, and re-scans the patch — auto-rollback on any gate failure
5. **Every action** is appended to a SHA-256 hash-chained audit ledger (tamper-evident, immutable)
6. **Alerts** are pushed in real-time via Telegram ChatOps

---

## Key Technical Highlights

| Feature | Details |
|:--------|:--------|
| **RAG + Metadata Filtering** | 55 secure-coding rules (8 languages) embedded into ChromaDB. At retrieval time, CWE ID + language filter ensures the LLM receives only the relevant rule — not generic advice |
| **Dual-Pipeline Benchmark** | Pipeline A: Cloud LLM (baseline). Pipeline B: local `qwen2.5-coder:7b` via Ollama with RAG. Both run in parallel; results measured on 11 real vulnerabilities |
| **Zero Trust Fail-Secure** | Secrets loaded from AWS Secrets Manager (Layer 1) → HashiCorp Vault (Layer 2). If both are unavailable, pipeline raises `CriticalSecurityException` and halts — no unsafe fallback |
| **3-Gate Validation + Self-Healing Rollback** | Compile → Unit Tests → Semgrep SAST. Any gate failure triggers automatic `git checkout` rollback. AI-generated code never reaches `master` if it breaks a gate |
| **File-Grouped Batch + Parallel Processing** | Vulnerabilities in the same file are batched into a single AI prompt (preventing code conflicts). Different files are processed in parallel via `ThreadPoolExecutor` |
| **Tamper-Evident Audit Ledger** | SHA-256 hash-chained ledger (single-node, append-only). Any modification to any historical entry is detected immediately on next integrity check |
| **Cloud-Ready Architecture** | Floci emulates AWS Secrets Manager locally. Moving to production AWS requires changing exactly one environment variable |

---

## Experimental Results

Tested on **11 representative CWEs** from a purposefully-vulnerable Java Spring Boot application:

| Metric | Pipeline A (Cloud LLM) | Pipeline B (Local RAG + Ollama) |
|:-------|:----------------------|:-------------------------------|
| Patch generation rate | 11/11 (100%) | 11/11 (100%) |
| Build success rate | **11/11 (100%)** | 10/11 (90.9%) |
| Avg. patch latency | ~19.4 s ⚡ | ~120.1 s |
| Data security | Low (cloud) | **High (on-premise)** |
| Cost | API fee | **Free** |
| Policy compliance | ✗ | **✓ via RAG** |
| Validation gates | 1 (compile only) | **3 (compile + test + SAST)** |

> **Key finding**: Both pipelines achieve 100% patch generation. Pipeline A is ~6× faster; Pipeline B provides stronger security guarantees via RAG-enforced policy compliance and 3-gate validation. Combined failover (A → B) achieves 100% build success across all 11 vulnerabilities.

---

## Architecture Overview

```
Developer Push
      │
      ▼
OneDev CI/CD ──► SonarQube (SAST) ──► DefectDojo (ASPM)
                                              │
                          ┌───────────────────┤
                          ▼                   ▼
               Pipeline A (Cloud)    Pipeline B (Local RAG)
               1-Gate Validation     3-Gate Validation
               (mvn compile)         (Compile + Test + SAST)
                          │                   │
                          └────────┬──────────┘
                                   │
                          Git push (hotfix/) ──or── Auto-Rollback
                                   │
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼
      SHA-256 Audit          Zero Trust Secrets    Telegram Alert
      Ledger (local)         AWS SM → Vault → FAIL
```

---

## Vulnerability Coverage (23 CWEs)

| # | Vulnerability | CWE | OWASP 2021 | Source File |
|---|:-------------|:----|:-----------|:-----------|
| 1 | SQL Injection | CWE-89 | A03 | `UserController.java` |
| 2 | Hardcoded Credentials | CWE-798 | A05 | `UserController.java` |
| 3 | Resource Leak / Bad Logging | CWE-772 | A09 | `UserController.java` |
| 4 | Cross-Site Scripting (Reflected XSS) | CWE-79 | A03 | `ProductController.java` |
| 5 | Path Traversal | CWE-22 | A01 | `ProductController.java` |
| 6 | Log Injection | CWE-117 | A09 | `ProductController.java` |
| 7 | Insecure Deserialization | CWE-502 | A08 | `ProductController.java` |
| 8 | Weak Cryptographic Hash (MD5) | CWE-327 | A02 | `AuthController.java` |
| 9 | Insecure Random | CWE-330 | A02 | `AuthController.java` |
| 10 | OS Command Injection | CWE-78 | A03 | `PingController.java` |
| 11 | Unrestricted File Upload + Path Traversal | CWE-434/22 | A04 | `FileController.java` |
| 12 | IDOR (Broken Access Control) | CWE-284 | A01 | `OrderController.java` |
| 13 | Server-Side Request Forgery (SSRF) | CWE-918 | A10 | `WebhookController.java` |
| 14 | XML External Entity (XXE) | CWE-611 | A05 | `XmlController.java` |
| 15 | Hardcoded / Weak JWT Secret | CWE-321 | A02 | `JwtUtils.java` |
| 16 | Open Redirect | CWE-601 | A01 | `SessionController.java` |
| 17 | Session Fixation + Missing Cookie Flags | CWE-384 | A07 | `SessionController.java` |
| 18 | ReDoS (Regex DoS) | CWE-1333 | A06 | `ReportController.java` |
| 19 | Sensitive Data in Error Messages | CWE-209 | A09 | `ReportController.java` |
| 20 | Missing Security Headers + CORS Wildcard | CWE-525 | A05 | `CacheController.java` |
| 21 | Credentials in URL Parameter | CWE-598 | A02 | `CacheController.java` |
| 22 | Null Pointer Dereference | CWE-476 | A03 | `UserController.java` |
| 23 | Broken Cipher (DES/ECB Mode) | CWE-327 | A02 | `CryptoController.java` |

---

## Tech Stack

**DevSecOps & Infrastructure**
- SonarQube · DefectDojo · OneDev CI/CD · Docker Compose · OWASP ZAP (DAST)

**AI & Machine Learning**
- LangChain · ChromaDB (vector store) · Ollama (`qwen2.5-coder:7b`, `nomic-embed-text`)
- OpenAI-compatible API (benchmark baseline)

**Security & Secret Management**
- HashiCorp Vault · AWS Secrets Manager (Floci local emulator · boto3)
- SHA-256 hash-chaining (audit ledger)

**Languages & Frameworks**
- Python 3.10+ · Java 11 (Spring Boot) · React (Vite) · Flask

---

## Quick Start

### Prerequisites
- Docker Desktop, Python 3.10+, Java 11+, Maven 3.6+, Git
- [Ollama](https://ollama.com) with `qwen2.5-coder:7b` and `nomic-embed-text` pulled

### 1. Clone & configure

```bash
git clone https://github.com/<your-username>/DevSecOpsLab.git
cd DevSecOpsLab
cp .env.example .env
# Fill in TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env
```

### 2. Start infrastructure

```bash
cd core-infra
docker compose up -d
# Wait ~60 s for SonarQube to initialize
```

| Service | URL | Credentials |
|---------|-----|-------------|
| SonarQube | http://localhost:9000 | admin / 123123 |
| HashiCorp Vault | http://localhost:8200 | token: dev_root_token |
| OneDev | http://localhost:7670 | — |

### 3. Initialize Zero Trust secrets

```bash
cd ..
python init_aws_secrets.py   # Layer 1 — AWS Secrets Manager (Floci)
python init_vault_secrets.py # Layer 2 — HashiCorp Vault

# Verify all 3 layers
python zero_trust_demo.py
```

### 4. Pull Ollama models

```bash
ollama pull qwen2.5-coder:7b
ollama pull nomic-embed-text
```

### 5. Run the AI auto-remediation pipeline

```bash
# Demo mode (no live DefectDojo required)
python experiment_runner.py --mode demo

# Live mode (full pipeline against real DefectDojo findings)
python auto_remediate_rag.py
```

### 6. Run the Blockchain Ledger integrity demo

```bash
python kb5_step1_verify.py   # Verify initial integrity
python kb5_step2_tamper.py   # Simulate data tampering
python kb5_step3_detect.py   # Detect broken hash chain
python kb5_step4_restore.py  # Restore from clean backup
```

---

## Project Structure

```
DevSecOpsLab/
├── auto_remediate_rag.py       ← Core AI engine: RAG + Metadata Filter + Batch/Parallel
├── auto_remediate.py           ← Pipeline A: Cloud LLM baseline
├── blockchain_ledger.py        ← SHA-256 tamper-evident audit ledger
├── experiment_runner.py        ← Benchmark: measures & compares both pipelines
├── zero_trust_demo.py          ← Interactive Zero Trust failover demo
├── aws_secrets_client.py       ← Zero Trust Layer 1 (AWS Secrets Manager)
├── vault_client.py             ← Zero Trust Layer 2 (HashiCorp Vault)
├── Secure_Coding_Guidelines.txt← Knowledge base: 55 rules across 8 languages (RAG source)
├── kb5_step{1-4}_*.py          ← Blockchain integrity demo scripts
├── demo_dashboard_api.py       ← Flask bridge API (port 5555)
├── demo-dashboard/             ← React dashboard (Vite, port 3000)
├── core-infra/
│   └── docker-compose.yml      ← SonarQube + OneDev + Vault + Floci
└── vulnerable-spring-boot/     ← Target app: 23 intentional vulnerabilities
    └── src/main/java/com/devsecops/
        ├── UserController.java
        ├── ProductController.java
        ├── AuthController.java
        └── ... (13 controllers)
```

---

## Security Notes

- ⚠️ `vulnerable-spring-boot` contains **intentional security flaws** for research purposes. Do **not** deploy to production.
- `.env` is gitignored — no secrets are committed to this repository.
- All runtime secrets are loaded via the Zero Trust 3-layer mechanism at startup.

---

## License

MIT © 2024 — Developed as a Bachelor's Thesis in Information Security

---

<div align="center">
  <strong>DevSecOps Lab</strong> · AI Auto-Remediation · Zero Trust · Tamper-Evident Audit Ledger<br>
  Built to demonstrate how security can be automated, enforced, and audited end-to-end.
</div>
