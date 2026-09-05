# Penetration Test Authorization & Rules of Engagement

**Engagement ID:** MP-2026-0904-INTERNAL
**Client:** MeridianPay Financial Technologies, Inc. (fictional — training use only)
**Engagement type:** Network + Web Application Penetration Test — Grey/Black Box, authenticated + unauthenticated
**Authorized tester:** You (sslash581@gmail.com), self-authorized for a local training lab
**Date issued:** 2026-09-04
**Testing window:** Open-ended — this is a standalone local lab, not a live engagement with a deadline

---

## 1. Purpose

MeridianPay Financial Technologies, Inc. has engaged the tester to assess the
security of its customer-facing online banking platform and the internal
network segment it sits on prior to a (fictional) SOC 2 audit. Unlike a
single-app assessment, this scope spans multiple hosts/services discovered
during reconnaissance — treat it the way you'd treat a real small-fintech
external footprint: find what's listening, fingerprint it, then go deep on
each service. This document defines scope, rules of engagement, and points
of contact for the assessment, in the style of a real client authorization
letter.

## 2. Target(s) — IN SCOPE

All targets are bound to `127.0.0.1` only and reachable solely from this
machine.

| Asset | Address | Notes |
|---|---|---|
| MeridianPay web application | `http://127.0.0.1:8000` | Public site, online banking portal, admin console, mobile API |
| MeridianPay internal ledger API | `http://127.0.0.1:8000/internal/*` | Reachable only from the app itself under normal use — treat as an internal-network-only endpoint for the exercise |
| MeridianPay mobile API | `http://127.0.0.1:8000/api/*` | JSON API backing a fictional mobile app |
| Core Banking Ops Console | `http://127.0.0.1:8081` | Internal change-management/diagnostics tool, mistakenly reachable outside its intended management segment |
| Ops Backup Relay | `ftp://127.0.0.1:2121` | Legacy FTP-style backup transfer service left running since a 2019 migration |
| Health/status probe | `tcp://127.0.0.1:9090` | Trivial banner service |

Discovering this full list is itself part of the exercise — start with
recon/port scanning against `127.0.0.1` rather than being handed the list
above as a checklist (it's given here only because a real authorization
letter names every in-scope host explicitly).

## 3. OUT OF SCOPE

- Any host, service, or port on this machine **other than** the six listed
  above. Do not pivot into the host OS beyond what a vulnerability in these
  services itself grants you (e.g., reading `core_flag.txt` via a command
  injection bug is in scope; going on to enumerate unrelated files on the
  tester's machine is not — this is a scoping-discipline exercise).
- Denial-of-service testing of any kind (no flooding, no resource
  exhaustion, no fork bombs via any of the RCE vectors).
- Any destructive action against the host filesystem outside this project
  directory (`/home/sslash/Projects/pentest/labs/lab2`).
- Real third parties. Do not point the "Verify Recipient Bank" tool
  (SSRF vector) at real external hosts — only at `127.0.0.1` targets within
  this lab.
- Automated mass-scanning tools configured with aggressive thread counts —
  these are single-threaded-friendly local targets; keep scan concurrency
  low out of good habit even though there's no real infrastructure to harm.

## 4. Rules of Engagement

1. **Authorization basis:** this letter. Keep it — in a real engagement you
   never test without one, and you should be able to produce it on request.
2. **Techniques authorized:** manual testing, proxying through Burp/ZAP,
   automated scanners (sqlmap, ffuf/gobuster, nmap, hashcat/john, hydra,
   etc.), custom scripts, and exploitation of any vulnerability you discover
   up to and including the code-execution vectors described in §6 — all
   confined to the targets in §2.
3. **Reporting:** not required for this solo exercise, but write findings up
   as if you were delivering a report to a client — CVSS-ish severity, an
   affected-asset table, reproduction steps, and remediation. That's the
   skill most eJPT/CJCA-style labs don't make you practice, and it's what
   separates "found the bug" from "got hired again."
4. **Data handling:** all data in this lab is synthetic. There is no real
   PII and no real money anywhere in this system.
5. **Emergency contact:** you. If something on your machine behaves
   unexpectedly (e.g. a runaway process from one of the RCE vectors), you
   have full authority to kill it — `pkill -f "python3 run.py"`.

## 5. Objectives

Assess the environment for vulnerabilities across the OWASP Top 10, common
network-service misconfigurations, and fintech-specific business-logic
flaws, and report/exploit anything found — including but not limited to:
injection flaws, broken authentication, broken access control, SSRF,
insecure deserialization, unrestricted file upload, and weak network
service hardening. A scored objective list (flag format `FLAG{...}`) is
provided in `README.md` so you can self-verify findings without a
walkthrough — try to get there without opening `SOLUTIONS.md`.

## 6. Special Authorization — Code Execution Vectors

Several independent vulnerabilities in this environment are exploitable to
achieve arbitrary code execution **in the context of the relevant service
process, on your own machine, under your own user account**:

- OS command injection in the KYC verification report tool (web app, admin)
- Insecure deserialization (`pickle`) in the legacy bulk-import tool (web
  app, admin)
- OS command injection in the Core Banking Ops Console's network
  diagnostics ping tool (port 8081)

All three are explicitly authorized as part of this engagement, including
using them to read `core_flag.txt` at the project root — a file that is
*not* reachable through any of the vulnerabilities above except via
code execution or the path-traversal bug, and exists specifically to prove
you achieved it. Standard caution applies: don't run anything you wouldn't
run on your own machine anyway (this is your machine), and don't use any of
these vectors to affect anything outside this project directory (see §3).

If you'd rather not have live RCE vectors on your daily-driver machine, run
the lab in a disposable VM or container instead — everything here is pure
Python 3 standard library, so `python3 run.py` is all any of it needs,
anywhere.

## 7. Duration & Sign-off

No fixed end date. Consider the engagement "closed" once you've either
captured all objectives in `README.md` or reviewed `SOLUTIONS.md` for the
ones you didn't get. Re-run `python3 run.py --reset` any time to restore a
clean environment and start over.

---

*Signed (self-authorization): sslash581@gmail.com, 2026-09-04*
