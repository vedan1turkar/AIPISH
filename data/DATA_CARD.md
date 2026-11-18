# AIPISH labelled email corpus — data card (R5)

Status: **prepared, not yet used for training.** The corpus is built by
`backend/app/ml/dataset/` and is fully reproducible from the pinned sources below.

## 1. Purpose and taxonomy

The corpus provides training, validation and test data for the AIPISH classifiers
(R1 DistilRoBERTa cues, R3 XGBoost/scikit-learn 5-class model). Target classes, in index order:

`legitimate`, `suspicious`, `impersonated`, `phishing`, `fraud`.

Class definitions used for labelling, with precedence top-down:

| Class | Definition |
|---|---|
| fraud | Asks the recipient to move money or change payment details (BEC wire, payroll or invoice redirect, gift cards, advance fee). |
| phishing | Tries to harvest credentials or account data, usually through a link or form. |
| impersonated | Poses as a known person, vendor, brand or internal function, but asks for no payment and gives no credential link (call-back, data or contact request). |
| suspicious | Unwanted or anomalous mail that is none of the above. **No approved source exists (see §9).** |
| legitimate | Ordinary wanted mail. |

## 2. Sources, licences and provenance

All sources were checked on 2026-11-18 against the provider's own pages. Raw files are
stored locally under `data/raw/<source>/`. Each directory has an `acquisition.json`
that records URL, size, SHA-256 and UTC acquisition time.

| Source | Files used | Licence / terms (as stated by the provider) | Redistribution |
|---|---|---|---|
| **Nazario phishing corpus**, https://monkey.org/~jose/phishing/ | `phishing0.mbox`, `phishing1.mbox`, `phishing2.mbox`, `phishing3.mbox`, `20051114.mbox` | **CC BY 4.0.** The corpus README says it is "CC-BY-4.0", and `LICENSE.txt` contains the CC BY 4.0 legal code. Attribution is required. The README also says the mail is hand-classified and may contain errors, and that earlier mailboxes were anonymised. | Permitted with attribution. We still keep the raw mail local, because it contains live phishing URLs. |
| **SpamAssassin public corpus**, https://spamassassin.apache.org/old/publiccorpus/ | `20030228_easy_ham.tar.bz2`, `20030228_easy_ham_2.tar.bz2`, `20030228_hard_ham.tar.bz2` (ham only) | **No licence is granted.** The readme says copyright stays with the original senders, and that the messages were posted to public fora, sent knowing they might be made public, or came from public newsletters. The readme also asks that the messages not be sent into a live mail system. | **Not granted.** Content is not committed; acquire it locally. |
| **Enron email dataset**, CMU, May 7 2015 version, https://www.cs.cmu.edu/~enron/ | `enron_mail_20150507.tar.gz`, sent folders only (sampled, §4) | **No formal licence.** FERC made the data public during its investigation. CMU distributes it as a research resource, asks users to respect the privacy of the people involved, and notes that some messages were removed at employees' request. | Not committed, because it is personal correspondence of real people. Acquire it locally. |
| **Synthetic (AIPISH)**, `backend/app/ml/dataset/synthetic.py` | 24 templates in 8 families, seed `20261118` | Project-generated. | Regenerated from code; nothing is stored. |

Required attribution: *Jose Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/,
licensed CC BY 4.0.* Changes made to the data: messages normalised, masked,
deduplicated and relabelled as described in this card.

Considered and **not used**:

- `nazario/private-phishing4.mbox`. The file name marks it "private" and the README does not explain its status.
- `nazario/phishing-2015…2025`. These have the same licence, but would widen the era gap to the 1998–2003 legitimate corpora. Deferred; see §9.
- SpamAssassin `spam` and `spam_2`. They are not an approved source for any AIPISH class, since spam is not phishing.

## 3. Label mapping

Original labels are preserved in `original_label`. The mapping lives in
`app/ml/dataset/labels.py` (`LABEL_MAP`). Any unmapped (source, label) pair is rejected.

| Source / original label | → class | Note |
|---|---|---|
| nazario / phishing | phishing | Author's hand classification, kept as-is. |
| spamassassin / easy_ham, easy_ham_2, hard_ham | legitimate | "Ham" means non-spam. hard_ham is marketing-like but wanted mail. |
| enron / sent_mail | legitimate | **Assumption.** Enron has no labels. Only mail from custodians' own `sent`, `sent_items` and `_sent_mail` folders is used, i.e. mail written by employees. |
| synthetic / bec_wire_transfer, bec_payroll_redirect, invoice_bank_change, gift_card_request, advance_fee | fraud | |
| synthetic / exec_impersonation, vendor_impersonation, it_support_impersonation | impersonated | |

No manual relabelling of individual messages was performed.

## 4. Preprocessing and exclusions

The same rules apply to every source (`normalize.py`):

- **Parsing.** Messages are parsed with the Python stdlib `email` parser (compat32).
- **Body.** text/plain parts are used, or HTML converted to text when there is no plain part. `<a href>` targets are kept as URL hosts.
- **Text cleanup.** Unicode NFC normalisation; invisible and control characters removed; whitespace collapsed; body truncated to 20,000 characters.
- **Masking.** E-mail addresses in the subject and body are replaced by `<EMAIL>`, and URLs by `<URL>`. URL hosts are kept separately in `url_hosts`. This stops source-specific sanitisation (for example `spamassassin.taint.org`) from becoming a label shortcut.
- **Recipients are never stored.** The sender address is stored only as a SHA-256; the sender domain is kept.
- **Dates.** Dates are converted to UTC ISO-8601. Dates outside 1990–2027, or unparsable, become null.
- **Enron sampling.** One streaming pass over the tarball. For each custodian, the 25 sent-folder messages with the smallest `sha256(path)` are kept. This is deterministic, and no custodian can dominate.
- **Exclusions.** The following are logged in `manifest/exclusions.csv`, one reason per message:
  - `empty_or_tiny_body`: body shorter than 20 characters after normalisation.
  - `mbox_internal_record`: the mbox folder-data pseudo-message.
  - `exact_duplicate_raw`: byte-identical file.
  - `exact_duplicate`: identical normalised subject and body; the first copy in source order is kept.
  - `exact_duplicate_label_conflict`: the same content under two labels; every copy is dropped.

## 5. Deduplication

- **Exact.** SHA-256 of the canonical subject plus the lower-cased, whitespace-collapsed masked body (`norm_sha256`).
- **Near-duplicate.** A 64-bit SimHash over word 3-shingles of the masked body. Messages within Hamming distance ≤ 6 are clustered, using 8 LSH bands (by the pigeonhole principle, any pair within distance 6 shares at least one band) and union-find. Quote markers are not tokens, and bodies with fewer than 10 tokens are only checked for exact duplicates.
- **Near-duplicates are kept, not deleted.** They define hard split groups, so no near-duplicate pair can straddle two splits.

## 6. Splits (train / validation / test = 70 / 15 / 15, stratified by class)

Implemented in `split.py`; fully deterministic.

1. **Hard groups (union-find).** Messages are joined when they share any of:
   - a near-duplicate cluster;
   - a thread (Message-ID, In-Reply-To or References);
   - a campaign key (same label and the same canonical subject, at least 12 characters and not generic);
   - a synthetic template id.

   A hard group is never split. Hard-key collisions across splits are checked and are 0 (§7).
2. **Senders: a soft constraint.** The sender key is the sender domain. For shared domains, it is the hashed sender address instead. Shared domains are free-mail, or any domain with more than 5% of the corpus, such as `enron.com`.
   - Making sender a hard link chained most of each real class into one group. In a trial on Nazario and SpamAssassin, sender-domain linking gave one group with 83% of legitimate mail and another with 64% of phishing. Mailing-list threads join posters, and forged brand senders join campaigns. That would make any representative validation or test set impossible.
   - Instead, hard groups that share a sender key are merged as long as the merged group stays at or below 150 messages (`SENDER_MERGE_CAP`). This keeps small senders whole, for example an Enron custodian or a mailing list.
   - Placeholder senders written by corpus sanitisation (`spamassassin.taint.org`) are not treated as a sender identity.
   - Groups are then placed largest first. Each goes to the split that still needs its classes and already holds most of its sender keys.
   - Residual overlap is reported. It comes mainly from forged brand senders, such as phishing "from" `ebay.com` across many independent campaigns. Every validation or test row has `sender_seen_in_train`. The rows where it is `False` form a **sender-disjoint** evaluation subset, which has zero sender overlap with train.
   - Sender and campaign keys are scoped to the label. A phishing message forging `amazon.com` is not the same sender as a genuine Amazon newsletter.
3. **Dates.** A temporal split is not used. The sources come from different eras (§9), so a date cut would place whole classes in one split. Date ranges per split are reported below.

## 7. Counts (generated by `python -m app.ml.dataset.build`; do not edit by hand)

<!-- BEGIN GENERATED COUNTS -->

Total messages: **11289** (real 10717, synthetic 572 = 5.1%).

| Source | legitimate | suspicious | impersonated | phishing | fraud | total |
|---|---|---|---|---|---|---|
| nazario | 0 | 0 | 0 | 3218 | 0 | 3218 |
| spamassassin | 4104 | 0 | 0 | 0 | 0 | 4104 |
| enron | 3395 | 0 | 0 | 0 | 0 | 3395 |
| synthetic | 0 | 0 | 207 | 0 | 365 | 572 |
| **all** | 7499 | 0 | 207 | 3218 | 365 | 11289 |

| Original label | count |
|---|---|
| enron/sent_mail | 3395 |
| nazario/phishing | 3218 |
| spamassassin/easy_ham | 2470 |
| spamassassin/easy_ham_2 | 1388 |
| spamassassin/hard_ham | 246 |
| synthetic/advance_fee | 75 |
| synthetic/bec_payroll_redirect | 74 |
| synthetic/bec_wire_transfer | 75 |
| synthetic/exec_impersonation | 75 |
| synthetic/gift_card_request | 72 |
| synthetic/invoice_bank_change | 69 |
| synthetic/it_support_impersonation | 57 |
| synthetic/vendor_impersonation | 75 |

| Split | legitimate | suspicious | impersonated | phishing | fraud | total | date range |
|---|---|---|---|---|---|---|---|
| train | 5249 | 0 | 146 | 2254 | 250 | 7899 | 1999-02-17 – 2007-12-28 |
| validation | 1125 | 0 | 25 | 482 | 49 | 1681 | 1999-04-07 – 2007-12-17 |
| test | 1125 | 0 | 36 | 482 | 66 | 1709 | 1999-09-17 – 2007-12-22 |

| Source | date range | missing/invalid date |
|---|---|---|
| nazario | 1999-04-07 – 2007-08-06 | 15 |
| spamassassin | 2002-01-02 – 2002-12-04 | 1 |
| enron | 1999-02-17 – 2002-07-12 | 0 |
| synthetic | 2000-01-02 – 2007-12-28 | 0 |

| Exclusion reason | count |
|---|---|
| empty_or_tiny_body | 299 |
| exact_duplicate | 1737 |
| exact_duplicate_raw | 6 |
| mbox_internal_record | 1 |

Near-duplicate clusters (≥2 members): 498 covering 1973 messages; largest 66.
Leakage groups: 2144; largest group 915 messages {'phishing': 915}.
Cross-split hard-key collisions (must all be 0): campaign_subject=0, group=0, near_dup_cluster=0, norm_sha256=0, synthetic_template=0, thread=0.
Sender keys: 1478; in more than one split: 31 (soft constraint, see Splits).

Sender-disjoint evaluation subset (validation/test messages whose sender never occurs in train):

| Split | legitimate | suspicious | impersonated | phishing | fraud | total | sender seen in train |
|---|---|---|---|---|---|---|---|
| validation | 1125 | 0 | 25 | 249 | 49 | 1448 | 233 |
| test | 1125 | 0 | 36 | 287 | 66 | 1514 | 195 |

manifest.csv sha256: `d8d583a30ffc85b81010485498cc3a2f4cdf0e2beb3ca677c0eaf13bb9f60ab7`

<!-- END GENERATED COUNTS -->

## 8. Files and reproduction

```
cd backend
.venv/bin/python -m app.ml.dataset.acquire       # downloads to data/raw/, verifies size + SHA-256
.venv/bin/python -m app.ml.dataset.build         # writes data/processed + data/manifest, refreshes §7
```

| Path | Tracked in git | Content |
|---|---|---|
| `data/raw/<source>/` | no | Original archives plus `acquisition.json`. Enron also has `sent_subset/` with an index. |
| `data/processed/emails.jsonl` | no | Full normalised records, including masked text, for DistilRoBERTa and XGBoost. |
| `data/manifest/manifest.csv` | yes | One row per kept message: id, split, label, source, original label, synthetic flag, hashes, group and cluster, sender-seen flag, date, sender domain. No text. |
| `data/manifest/exclusions.csv` | yes | Every dropped message and the reason. |
| `data/manifest/stats.json` | yes | The numbers in §7, including the SHA-256 of `manifest.csv`. |

The source SHA-256 digests are pinned in `sources.py` after the first verified download.
A changed upstream file fails acquisition loudly rather than silently changing the corpus.
`tests/unit/test_dataset.py` checks the following:

- label validity and mapping;
- duplicate handling;
- leakage;
- synthetic separation;
- reproducibility;
- that this card's §7 equals what `stats.json` and `manifest.csv` contain.

## 9. Known limitations and class imbalance

- **No `suspicious` samples.** No approved source covers this class. It has 0 samples until a source is approved, for example SpamAssassin `spam`, which is not approved. A classifier trained on this corpus cannot predict `suspicious`.
- **Era confound.**
  - Legitimate mail spans 1998–2003 (Enron and SpamAssassin).
  - Phishing spans 2004–2007 (Nazario files used).
  - Vocabulary, HTML style and brand names differ by era. Models must not use dates, and should be evaluated with this in mind. Adding Nazario 2015–2025 together with modern legitimate mail would reduce the gap. Both would need approval.
- **Source confound.** Each class comes from one or two sources, so a model can partly learn "which corpus". Masking removes the most obvious artefacts, but corpus-specific features remain: Enron vocabulary, mailing-list footers and Nazario's anonymisation.
- **Synthetic classes.** `impersonated` and `fraud` are 100% synthetic and template-based: 24 templates in 8 families. Real BEC is far more varied. Their test scores measure generalisation to *unseen templates* only, not to real-world BEC. Synthetic data is kept at no more than 15% of the corpus, and never outnumbers real data within a class that has real data.
- **Label noise.** Nazario is hand-labelled by one person, and the author notes it may contain errors. Enron "legitimate" is an assumption, since sent folders can still contain forwarded spam or jokes.
- **Imbalance.** See §7. Training should use class weights or resampling. Metrics should be macro-averaged and per-class.
- **Language.** Predominantly English. No language filter was applied.

## 10. Usage restrictions

- Research and education within the AIPISH project.
  - SpamAssassin and Enron content must not be redistributed, committed or published.
  - Nazario content may be shared only with CC BY 4.0 attribution.
- Never send corpus messages into a live mail system (SpamAssassin readme request). Never open the URLs: Nazario URLs were live phishing links.
- Respect the privacy of the Enron custodians. Do not publish names, addresses or message excerpts from Enron in reports or demos.
  The committed manifest contains only provenance pointers: Enron mailbox paths such as `maildir/<custodian>/sent/…`, which are already public in the CMU release, plus hashes. It contains no message text.
- Synthetic samples use only fictional names and reserved `.test` / `.example` domains. They carry `X-AIPISH-Synthetic: true`, `source=synthetic` and a `synthetic_template` id, and must always be reported separately from real-data results.
