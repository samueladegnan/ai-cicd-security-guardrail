# AI-Driven CI/CD Security Guardrail Report
## Summary
- **Total findings triaged:** 2
- **High-priority security risks:** 1
- **False positives:** 1
- **Unclear:** 0
## Findings
### CWE-121 @ `sample_code/vulnerable.c:14`
- **Verdict:** HIGH_PRIORITY
- **Confidence:** 0.85
- **Severity:** HIGH
- **Message:** Possible stack-based buffer overflow due to unchecked strcpy.
- **Reasoning:** Mock triage based on keyword signals in the prompt and code context. High signals=True, false-positive signals=False.
- **Compliance controls:**
  - CERT_C STR31-C: STR31-C. Guarantee that storage for strings has sufficient space
- **Remediation:** Apply the appropriate secure-coding fix.

### unused-variable @ `sample_code/false_positive.c:13`
- **Verdict:** FALSE_POSITIVE
- **Confidence:** 0.80
- **Severity:** LOW
- **Message:** Local variable 'result' is assigned but never used.
- **Reasoning:** Mock triage based on keyword signals in the prompt and code context. High signals=False, false-positive signals=True.
- **Remediation:** Apply the appropriate secure-coding fix.

