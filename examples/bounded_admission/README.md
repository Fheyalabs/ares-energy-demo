# Bounded Admission — ARES-BC Example

A worked example demonstrating the ARES-BC (homomorphic bound check) on the
ARES framework: admit parties whose encrypted input vector satisfies a
committed bound, e.g., `‖x‖² ∈ [1−ε, 1+ε]` via the `NormCircuit`.

## Pipeline

```
Invitation → Keygen (pre-shared) → SubmitInput → boundcheck.Phase → Settle
```

- **Invitation** (`ADMISSION_INVITING → ADMISSION_LOCKED`): seeds the participant
  list and crypto contract (depth=8, ring_dim=16384).
- **Keygen** (`ADMISSION_LOCKED → ADMISSION_SUBMITTING`): pre-shared — the trigger
  injects collective PK, eval keys, and secret shares via admin POST attrs.
- **SubmitInput** (`ADMISSION_SUBMITTING → ADMISSION_CHECKING`): each participant
  submits `admission.input` carrying `{"enc_x":"<hex>"}`.
- **boundcheck.Phase** (`ADMISSION_CHECKING → ADMISSION_SETTLED`): the framework
  phase from `pkg/ares/phase/boundcheck`. Homomorphically evaluates
  `‖x − c‖²`, fuses partial decrypts, classifies against the bound, and records
  violators via the `ViolationHandler`.
- **Settle** (`ADMISSION_SETTLED → terminal`): broadcasts results and terminates.

## Message Types

| Direction | Type | Payload |
|---|---|---|
| Client → Server | `admission.input` | `{"enc_x":"<hex serialized ciphertext>"}` |
| Server → Client | `bound_check.challenge` | `{"enc_check":"<hex>","commitment":"<hex>"}` (unicast) |
| Client → Server | `bound_check.partial` | `{"<checkedParty>":"<hex partial>"}` |

## Commitment

The server binds each `enc_check` to the submitted input:
```
check_commitment = SHA256(enc_check || SHA256(enc_x) || session_id)
```
Clients verify this before submitting their partial. The Swift and Kotlin
`BoundCheckParticipant` implementations (in `clients/`) perform the verification
implicitly.

## Running

### Stub mode (no FHE)
```bash
go build ./examples/bounded_admission/cmd/session-service
./session-service &
curl -sS http://localhost:8000/admin/sessions -d '{
  "session_id": "adm-001",
  "participants": ["p0","p1","p2"]
}'
```

### Real FHE (`-tags openfhe`)
Requires system OpenFHE 1.5.1.
```bash
go build -tags openfhe ./examples/bounded_admission/cmd/session-service
./session-service &
curl -sS http://localhost:8000/admin/sessions -d '{
  "session_id": "adm-001",
  "participants": ["p0","p1","p2"],
  "attrs": {
    "collective_pk": "<hex>",
    "eval_mult_final": "<hex>",
    "eval_sum_final": "<hex>",
    "dim": 8
  }
}'
```

## Client Participants

- **Swift:** `clients/swift/Sources/AresClientFHE/BoundCheckParticipant.swift`
- **Kotlin:** `clients/kotlin/ares-client-fhe/` (Phase 2)

## License

Apache-2.0
