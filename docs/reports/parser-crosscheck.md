# Parser cross-check (P5k-lite, R43)

At upload, AIPISH parses the same raw bytes with a **second, independent parser**, then compares
normalised views of both parses:

- primary: the stdlib `email` package with `policy=default`, which AIPISH already uses;
- secondary: [mail-parser](https://pypi.org/project/mail-parser/) 4.10.0, pinned, pure Python, no
  required dependencies, built on the stdlib `compat32` policy.

The raw bytes exist at upload time even in `hash_only` mode.

> **Informational only.** The result never feeds the rule score, ML features, combined risk or alerts.
> Tests compare uploads with and without the cross-check and find identical rule, risk and alert outputs.

Parser differentials can indicate evasion attempts: a gateway and a mail client reading different senders,
attachments or MIME structure. They are often harmless decoding or folding differences.

## What is compared

| Field | Severity when different |
|---|---|
| From, Reply-To, Return-Path addresses | **security-relevant** |
| Received chain: hop count, order, `by` host and from-clause IPs per hop | **security-relevant** |
| Attachments: count, content type, SHA-256 and size | **security-relevant** |
| Attachment file names (compared as hashes) | info |
| MIME structure: leaf part count, nesting depth, boundary/nesting defects reported by either parser | **security-relevant** |
| Duplicate single-instance headers: From, Return-Path, Reply-To, Sender | **security-relevant** |
| Duplicate single-instance headers: To, Cc, Subject, Date, Message-ID, MIME-Version, Content-Type | info |
| To, Cc recipients | info |
| Subject (compared as a hash; never stored), Date, Message-ID | info |
| Body charsets | info |

Duplicate headers are counted from the raw header block, independently of both parsers.

## Result

The result is stored in `analysis.parser_crosscheck` (migration step 10, an additive JSON column). It is
exposed as `parser_crosscheck` on the analysis API.

- **`status`:** one of the following.

  | Status | Meaning |
  |---|---|
  | `agree` | No differences |
  | `minor_differences` | Info-level differences only |
  | `security_relevant_differences` | At least one security-relevant difference |
  | `unavailable` | The check did not run; `reason` says why |

- **`differences[]`:** each has a `field`, a `severity` (`info` or `security_relevant`), a system-written
  description and an `evidence_id` (`P1`, `P2`, …, the same scheme as `E`, `A` and `K` ids elsewhere).
- **`compared`:** hop, attachment and body-part counts for both parsers.
- **Also recorded:** the parser names and the mail-parser version.

**No email content is stored:** only field names, counts, severities and fixed descriptions. There are no
addresses, subjects, file names or header values, so viewers see the same result as analysts.

**Bounds:**

- messages above `PARSER_CROSSCHECK_MAX_MB` (default 10) are skipped;
- the check is limited to `PARSER_CROSSCHECK_TIMEOUT_SECONDS` (default 5);
- import or parse failures give `unavailable` with a reason, and the upload is unaffected.

## Where it appears

- The **Headers & relay** tab: a "Parser cross-check · informational" panel with a status badge (with
  text), the differences table and an explanation.
- PDF section 5 and HTML section 5: a short subsection.
- Redacted analyses show "redacted per retention policy".

## Verified behaviour (tests)

| Sample | Result |
|---|---|
| All normal fixtures (BEC, legitimate, phishing, macro, Tor, benign, multihop, multipart) | `agree` |
| Duplicate From headers | security-relevant: `duplicate_header:from` |
| Two Return-Path headers with different addresses | security-relevant: `return_path` and `duplicate_header:return-path` |
| Folded From with an extra address on a continuation line | security-relevant: `from` |
| Unclosed MIME boundary | security-relevant: `mime_structure` (CloseBoundaryNotFoundDefect) |
| Nested multipart reusing the outer boundary | security-relevant: `attachments` (0 vs 1) and `mime_structure` |
| Duplicate Date | minor: `duplicate_header:date` |
| Malformed Received (no structure, empty, no semicolon) | `agree`: both parsers keep the raw clauses, so this class is **not** detected |

## Limits

- Only two parsers. Real gateways and clients use others, so agreement is not proof of safety.
- Malformed Received headers that both parsers keep verbatim are not flagged. Received ordering, length and
  host/IP differences are flagged when they occur.
- Inline parts (images with a Content-ID) are excluded from the attachment comparison on both sides.
