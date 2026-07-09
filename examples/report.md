# AutoTriage Evaluation Report

Scored **15** findings — **7/15** fully correct.

## Metrics

| Metric | Value |
| --- | --- |
| Verdict precision (true_positive) | 100.0% |
| Verdict recall (true_positive) | 100.0% |
| Verdict F1 (true_positive) | 100.0% |
| Verdict accuracy (all findings) | 100.0% |
| Severity agreement (true positives) | 38.5% |
| Classifier TP / FP / FN | 13 / 0 / 0 |
| Abstentions (needs_human) | 0 |

## Verdict Confusion Matrix

| expected \ predicted | true_positive | false_positive | needs_human |
| --- | --- | --- | --- |
| true_positive | 13 | 0 | 0 |
| false_positive | 0 | 2 | 0 |
| needs_human | 0 | 0 | 0 |

## Per-finding Results

| Finding | Expected | Predicted | Severity (exp/pred) | Result |
| --- | --- | --- | --- | --- |
| sast-sqli-001 | true_positive | true_positive | high / critical | ❌ fail |
| secret-awskey-002 | true_positive | true_positive | critical / critical | ✅ pass |
| sast-cmdinj-003 | true_positive | true_positive | high / critical | ❌ fail |
| sast-eval-004 | true_positive | true_positive | high / critical | ❌ fail |
| sast-md5-005 | true_positive | true_positive | medium / high | ❌ fail |
| sast-pickle-006 | true_positive | true_positive | high / critical | ❌ fail |
| sast-flaskdebug-007 | true_positive | true_positive | medium / critical | ❌ fail |
| sca-requests-008 | true_positive | true_positive | high / high | ✅ pass |
| sca-pyyaml-009 | true_positive | true_positive | critical / high | ❌ fail |
| sca-flask-010 | true_positive | true_positive | medium / medium | ✅ pass |
| iac-s3public-011 | true_positive | true_positive | high / high | ✅ pass |
| iac-sgopen-012 | true_positive | true_positive | high / high | ✅ pass |
| iac-s3noenc-013 | true_positive | true_positive | low / medium | ❌ fail |
| sast-sqli-fp-014 | false_positive | false_positive | info / info | ✅ pass |
| secret-fp-015 | false_positive | false_positive | info / info | ✅ pass |
