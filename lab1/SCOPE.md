# Penetration Test Authorization & Rules of Engagement

**Engagement ID:** NF-2026-0902-INTERNAL
**Client:** NovaFreight Logistics Inc. (fictional — training use only)
**Engagement type:** Web Application Penetration Test — Grey/Black Box, authenticated + unauthenticated
**Authorized tester:** You (sslash581@gmail.com), self-authorized for a local training lab
**Date issued:** 2026-09-02
**Testing window:** Open-ended — this is a standalone local lab, not a live engagement with a deadline

---

## 1. Purpose

NovaFreight Logistics Inc. has engaged the tester to assess the security of its
public marketing site, customer portal, support desk, and internal admin/API
tooling prior to a (fictional) production launch. This document defines scope,
rules of engagement, and points of contact for the assessment, in the style of
a real client authorization letter — so you get practice reading and working
within one.

## 2. Target(s) — IN SCOPE

| Asset | Address | Notes |
|---|---|---|
| NovaFreight web application | `http://127.0.0.1:8000` | Public site, customer portal, support desk, admin panel |
| NovaFreight internal API | `http://127.0.0.1:8000/internal/*` | Reachable only from the app itself under normal use — treat as "internal network" for the exercise |
| NovaFreight mobile API | `http://127.0.0.1:8000/api/*` | JSON API backing a fictional mobile app |

The application binds to `127.0.0.1` only and is not reachable from other
hosts. Scope is limited to this single instance on this machine.

## 3. OUT OF SCOPE

- Any host, service, or port on this machine **other than** the NovaFreight
  app itself (127.0.0.1:8000). Do not pivot into the host OS beyond what a
  vulnerability in the app itself grants you (e.g., reading `flag.txt` via a
  path traversal bug is in scope; going on to enumerate unrelated files on
  the tester's machine is not — this is a scoping discipline exercise).
- Denial-of-service testing of any kind (no flooding, no resource
  exhaustion, no `fork()` bombs via the SSTI RCE vector).
- Any destructive action against the host filesystem outside this project
  directory (`/home/sslash/Projects/pentest/labs/lab1`).
- Real third parties. Do not point the "Carrier Label Fetch Tool" (SSRF
  vector) at real external hosts, only at `127.0.0.1` targets within this
  app.
- Automated mass-scanning tools configured with aggressive thread counts —
  this is a single-threaded-friendly local target; keep scan concurrency
  low out of good habit even though there's no real infrastructure to harm.

## 4. Rules of Engagement

1. **Authorization basis:** this letter. Keep it — in a real engagement you
   never test without one, and you should be able to produce it on request.
2. **Techniques authorized:** manual testing, proxying through Burp/ZAP,
   automated scanners (sqlmap, ffuf/gobuster, nikto, etc.), custom scripts,
   and exploitation of any vulnerability you discover up to and including
   the code-execution vector described in §6 — all confined to the target
   in §2.
3. **Reporting:** not required for this solo exercise, but consider writing
   findings up as if you were delivering a report to a client — it is the
   skill most eJPT/OSCP-style labs don't make you practice, and it is what
   separates "found the bug" from "got hired again."
4. **Data handling:** all data in the app is synthetic. There is no real PII.
5. **Emergency contact:** you. If something on your machine behaves
   unexpectedly (e.g. runaway process from the RCE vector), you have full
   authority to kill it — `pkill -f "python3 run.py"`.

## 5. Objectives

Assess the application for vulnerabilities across the OWASP Top 10 and
report/exploit anything found, including but not limited to: injection
flaws, broken access control, broken authentication, security
misconfiguration, vulnerable file handling, and SSRF. A scored objective
list (with flag format `FLAG{...}`) is provided in `README.md` so you can
self-verify findings without a walkthrough — try to get there without
opening `SOLUTIONS.md`.

## 6. Special Authorization — Code Execution Vector

One vulnerability in this application (server-side template injection in
the "message preview" feature on `/contact`) is exploitable to achieve
arbitrary Python code execution **in the context of the lab server
process, on your own machine, under your own user account.** This is
explicitly authorized as part of this engagement. Standard caution
applies: don't run anything you wouldn't run on your own machine anyway
(this is your machine), and don't use the vector to affect anything
outside this project directory (see §3).

If you'd rather not have a live RCE vector on your daily-driver machine,
run the app in a disposable VM or container instead — the app has zero
third-party dependencies, so `python3 run.py` is all it needs anywhere.

## 7. Duration & Sign-off

No fixed end date. Consider the engagement "closed" once you've either
captured all objectives in `README.md` or reviewed `SOLUTIONS.md` for the
ones you didn't get. Re-run `python3 run.py --reset` any time to restore a
clean environment and start over.

---

*Signed (self-authorization): sslash581@gmail.com, 2026-09-02*
