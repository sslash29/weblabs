# Rules of Engagement — Lab 3: Meridian Global Freight Portal

| | |
|---|---|
| **Engagement type** | Authorized web application penetration test (self-hosted training lab) |
| **Client** | Meridian Global Freight (fictional — lab entity only) |
| **Tester** | sslash |
| **Environment** | Local Docker Compose deployment, isolated to the tester's own machine |
| **Authorization** | Self-authorized. This is the tester's own lab infrastructure, built for personal certification practice (eJPT / CJCA / CWES track). No third party owns or operates any system in scope. |
| **Status** | Active |

## 1. Objective

Assess the Meridian Global Freight customer & operations portal for exploitable
vulnerabilities and demonstrate a full attack chain from unauthenticated
recon to internal-network compromise, in the style of a real black-box /
grey-box web app engagement. Five flags are distributed across the chain at
increasing difficulty; each stage is intended to unlock context (credentials,
hostnames, access) needed for the next.

## 2. Scope

### 2.1 In scope

| Target | Notes |
|---|---|
| `http://127.0.0.1:8080` (or `http://localhost:8080`) | Public-facing customer/ops portal. Primary entry point. |
| Any host discovered to be reachable **from within** the `meridian-web` container as a result of a vulnerability in the in-scope application (e.g. via SSRF or command execution) | Internal pivot targets are in scope *only* as reached through the application itself, not via direct host-to-host network access outside the app's own trust boundary. |
| `meridian-web` and `meridian-internal` Docker containers, and the `front`/`back` Docker networks defined in `docker-compose.yml` | |

### 2.2 Out of scope

- The Docker host machine itself, the Docker daemon/socket, and any other container or service not defined in this repository's `docker-compose.yml`.
- `../lab1` and `../lab2` and any other directory in this workspace — unrelated engagements, do not touch.
- Any real, non-lab internet-facing system. This lab does not call out to real third-party services; do not point exploit payloads (SSRF, webhooks, DNS exfil, etc.) at anything other than the lab's own containers.
- Denial-of-service testing, resource-exhaustion fuzzing, or anything intended to crash/degrade the environment rather than demonstrate a control failure.
- Physical access, social engineering, and supply-chain attacks against the tooling itself (npm/pip package tampering, etc.).

### 2.3 Authorized techniques

Standard black-box/grey-box web app testing is authorized against in-scope targets, including but not limited to: reconnaissance and enumeration, manual and automated vulnerability scanning, authentication and session testing, injection testing (SQL, command, template, etc.), authorization/IDOR testing, file upload abuse, SSRF, insecure deserialization, and credential cracking of hashes obtained *from the lab itself* (no external wordlists targeting real third parties).

## 3. Rules of engagement

1. All testing stays within the containers and networks defined in this lab. Do not pivot to the host OS beyond what the application's own vulnerabilities legitimately expose (i.e., getting a shell *inside* `meridian-web` is in scope; using that shell to attack the Docker host or other unrelated containers is not).
2. No destructive actions against the lab infrastructure itself beyond what's needed to prove impact (e.g., reading a flag file is fine; deleting the database or corrupting the filesystem so the lab can't be reset is not — if you need a clean slate, use `docker compose down && docker compose up --build` instead).
3. Findings should be documented as you go (target, vulnerability class, request/response evidence, impact) — treat this like a real assessment you'll write up afterward.
4. This is a single-tenant lab you own outright; the usual "don't test what you don't own" constraint is satisfied by construction, but the discipline of respecting the written scope is the point of the exercise.

## 4. Objectives / flag chain

Five flags, in the format `MERIDIAN{...}`, gating progressively deeper access:

1. **Flag 1** — Broken access control on an authenticated resource.
2. **Flag 2** — Chained injection + offline credential attack to reach a privileged role.
3. **Flag 3** — Remote code execution from an authenticated admin feature.
4. **Flag 4** — Network segmentation bypass to reach an internal-only service.
5. **Flag 5** — Full compromise of the internal service via an unsafe deserialization sink.

No further technique hints are given here — see `README.md` for setup and `walkthrough/` for a spoiler-gated solution guide if you get stuck.

## 5. Timeline

No fixed end date — this is a standing personal training lab. Rebuild with `docker compose up --build` at any time to reset to a known-good state.

## 6. Reporting

On completion, write findings up as you would for a client: affected endpoint, root cause, reproduction steps, CWE/OWASP mapping, severity (CVSS if you want the practice), and remediation. `../lab1` has an example report format (`NovaFreight_Pentest_Report_v5.docx`) you can use as a template.
