# Model cards

Version 1.0.0. Both deployed artifacts are JSON data, not executable pickle files.

## URL lexical model

- Input: lowercased URL with HTTP(S) scheme removed and trailing slash removed; maximum 4,096 characters at inference.
- Features: character TF-IDF, n-grams 2–5, 18,000 features, `min_df=2`, sublinear term frequency, L2 normalization.
- Classifier: logistic regression (`C=4`, liblinear, seed 42). Multinomial Naive Bayes (`alpha=.5`) is evaluated as a comparator.
- Calibration: separate logistic sigmoid fit on classifier decision scores using the calibration split. Threshold 0.48, chosen by validation F1.
- Split counts: train 35,411; validation 5,338; calibration 6,874; test 12,377. Counts vary around 60/10/10/20% because groups stay together.
- Test: precision 0.930286; recall 0.817206; F1 0.870088; Brier 0.083573. Confusion matrix `[[6641,331],[988,4417]]`, rows true class, columns predicted class, class order `[legitimate, phishing]`.

The URL model misses 988 test positives and falsely flags 331 test negatives. Legitimate long paths, unfamiliar domains, and URL templates resembling historical campaigns can be flagged. Short modern phishing URLs, compromised legitimate domains, and shortened destinations can be missed. This lexical model cannot observe page content, redirects, reputation, or ownership.

## Email spam model

- Input: decoded subject plus email body; maximum 30,000 characters.
- Features: word TF-IDF, unigrams/bigrams, 18,000 features, `min_df=2`, sublinear frequency, L2 normalization.
- Classifier and calibration: same linear approach as URL, separate email training data and coefficients.
- Split counts: train 2,688; validation 448; calibration 448; test 896. Threshold 0.16 selected on validation F1.
- Test: precision 0.955145; recall 0.997245; F1 0.975741; Brier 0.012468. Confusion matrix `[[516,17],[1,362]]`, class order `[ham, spam]`.

The email model predicts **spam**, not phishing. The corpus is decades old; apply its measured results only to this held-out corpus. Modern legitimate marketing and security notices may look spam-like. Concise or targeted phishing may look like ordinary email. OCR screenshot text is explicitly marked outside this model’s training domain. No screenshot-level performance claim is made.

## Risk fusion and explanations

There is no invented aggregate percentage. Ordinal categories use a documented policy: brand-domain misuse, URL userinfo, or pressure combined with credential/payment language yields **high concern**; any other warning/model-positive signal yields **needs review**; otherwise **few indicators**. These rules can misinterpret quoted or educational language. High concern recommends verification; it is not a definitive maliciousness label.

Model probabilities, thresholds and positive class are displayed separately. Feature contributions are the additive linear TF-IDF terms, before calibration. They explain the statistical model but are not causal proof. The test suite verifies portable inference against scikit-learn outputs to 1e-6 on authored parity examples. Explanation completeness is also checked through deterministic signal tests. No human explanation-quality study or visual brand-recognition evaluation has been conducted.

## Evaluation boundary

Independent train/validation/calibration/test groups prevent exact known group overlap. No time-separated evaluation, external independent corpus, adversarial benchmark, language-coverage study, or real-user trial has been performed. Corpus artifacts, collection biases and near-duplicate campaigns may inflate performance. The final combined policy has not been calibrated as a probabilistic classifier. Re-evaluate with recent, consented and independently labeled data before making efficacy claims.
