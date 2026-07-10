# AutoTriage Fix-Validation Report

Validated **3** proposed fixes — **2/3** confirmed resolved by re-scan.

Each fix is applied to an isolated copy of the target and the scanner re-run; a fix is trusted only when the finding is gone and no new finding is introduced.

| Finding | Status | Resolved | Before | After | New findings | Detail |
| --- | --- | --- | --- | --- | --- | --- |
| 66f87406fa87 | resolved | ✅ | 25 | 24 | — | finding no longer fires and no new findings were introduced |
| 69aaed1f4f00 | resolved | ✅ | 25 | 24 | — | finding no longer fires and no new findings were introduced |
| 26ce609f12fe | unresolved | ❌ | 25 | 25 | — | the finding still fires after applying the fix |
