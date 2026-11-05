# Dataset documentation

## URL: PhiUSIIL

Source: [UCI PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), Arvind Prasad and Shalini Chandra, 2024. [Paper DOI](https://doi.org/10.1016/j.cose.2023.103545). UCI lists the dataset under **CC BY 4.0**.

The original archive contains 235,795 URL records with many webpage-derived features. PhishGuardX uses only the URL string and label. Source labels are `1 = legitimate`, `0 = phishing`; the pipeline explicitly inverts them to `1 = phishing`. No webpage is downloaded during training or inference. URLs are lowercased, scheme-stripped, trailing-slash-normalized, deduplicated, then sampled to 60,000 rows with random seed 42. Removing the scheme reduces the risk of learning dataset-specific HTTPS differences as a shortcut.

The split uses offline Public Suffix List parsing and grouped splits by registered domain. All four split group sets are asserted disjoint. The vocabulary and IDF values are fitted on training data only. Dataset archives, URLs and raw CSVs are not committed. Download URL and archive SHA-256 are recorded in `backend/models/evaluation.json`.

## Email: SpamAssassin public corpus

Source: [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) and its [readme](https://spamassassin.apache.org/old/publiccorpus/readme.html).

Archives: `20030228_easy_ham`, `20030228_hard_ham`, `20030228_spam`, and `20050311_spam_2`. These are historically labeled ham/spam emails, **not phishing labels**. The messages were donated for filter research; individual message rights remain with their original authors. This repository redistributes no raw messages. Consult the corpus terms before reusing or redistributing data.

The parser extracts subjects and non-attachment text parts, strips HTML tags, handles unknown charsets, normalizes whitespace, and limits text length. Fingerprints normalize case, whitespace, digit runs and URL strings; duplicates are removed and groups remain disjoint. After deduplication, 4,480 messages remain. Similar campaigns with substantially changed text can still cross groups; this is a known leakage limitation, not a claim of perfect campaign isolation.

## Reproduction

Run `python ml/train.py` from a virtual environment containing `ml/requirements.txt`. Pin versions, seed, source archives and checksums when comparing runs. Public Suffix List snapshots are bundled with the pinned tldextract release; no runtime PSL request occurs. The test set is not used to select features, models, thresholds or calibration coefficients.
