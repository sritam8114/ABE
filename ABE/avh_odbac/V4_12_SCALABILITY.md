# AVH-ODBAC V4.12 Scalability Evaluation

## Overview

V4.12 extends the distributed MPC integration prototype to configurable
attribute-universe sizes. It uses the V3 session-scoped token implementation,
actual ciphertext and trapdoor generation, bilateral policy matching,
authorization gating, and functional decryption verification.

## Experimental results

| Attributes | Triples prepared | Triples consumed | Inner product | Verification |
|---:|---:|---:|---:|---|
| 2 | 30,000 | 7,037 | 7 | PASS |
| 4 | 100,000 | 24,889 | 18 | PASS |
| 6 | 150,000 | 53,845 | 33 | PASS |
| 8 | 200,000 | 94,193 | 52 | PASS |
| 10 | 250,000 | 146,221 | 75 | PASS |

All five reported authorized experiments passed the authorization gate,
V3 matching-equivalence check, and functional decryption check.

Machine-readable results are in `benchmark_results_v412_scalability.csv`.

## Interpretation

Beaver triple consumption increased with the tested attribute count.
These are implementation-specific measurements, not a theoretical
complexity proof. Comparable execution-time and communication-volume
measurements are not included.

## Security and deployment limitations

- SS512 provides approximately 80-bit security, below the recommended
  128-bit level.
- CSP-1 and CSP-2 are separate processes on the same VM.
- Communication uses loopback TCP without TLS or authentication.
- The preprocessing dealer and local filesystem remain trusted.
- MSP structure and public group components remain visible.
- The verifier reconstructs returned result shares.
- No formal security proof or malicious-security claim is made.

These results demonstrate prototype functionality and measured triple
consumption, not production security.
