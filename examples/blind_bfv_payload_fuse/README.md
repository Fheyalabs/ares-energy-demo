<!-- SPDX-License-Identifier: Apache-2.0 -->

# Blind BFV Payload Fuse

Production-shaped BFV example for the ring-32k blind packed-integer payload
fusion path.

This package intentionally keeps the heavy OpenFHE run behind manual tests and
profiles. The exported helpers pin the measured profile and lineage roles so an
application can bind BFV artifacts without baking app policy into ARES-core.

Profile:

- ring dimension `32768`
- plaintext modulus `65537`
- batch/profile slots `128`
- package bytes `80`
- int7 quantization scale `63`
- exact step-polynomial bits `13`
- process parallelism disabled by default

Apps decide whether this profile is primary, fallback, lazy, or pre-staged.
