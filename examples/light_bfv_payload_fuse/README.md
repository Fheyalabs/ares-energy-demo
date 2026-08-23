<!-- SPDX-License-Identifier: Apache-2.0 -->

# Light BFV Payload Fuse

Fast BFV example using the same threshold packed-integer scheme shape as the
ring-32k blind BFV profile, but with smaller dimensions for CI and local smoke
tests.

It demonstrates:

- named additive BFV profiles
- deterministic signed integer quantization
- byte payload slot encoding
- ciphertext-lineage commits for BFV artifacts

The heavy production-shaped circuit lives in `examples/blind_bfv_payload_fuse`.
