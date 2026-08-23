# SPDX-License-Identifier: Apache-2.0
"""Python IPC client for cmd/openfhe-contract-helper.

Spawns the helper as a long-lived subprocess in daemon mode and
exchanges newline-delimited JSON envelopes over stdin/stdout. Mirrors
``pkg/ares/crypto/helperclient`` (Go) so smoke flows and server
phases share one wire format.

Usage:

    helper = OpenFHEHelper(binary_path="/path/to/openfhe-contract-helper")
    await helper.start()
    params = ContractParams(ring_dim=16384, depth=30, scaling_mod_size=40)
    share = await helper.keygen_first(params)
    ...
    await helper.close()

The helper does not retain state between ops — every call carries
``params`` and the helper rebuilds the CryptoContext. Callers
typically reuse one helper per worker thread to amortize startup
cost.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from typing import Any


class HelperError(RuntimeError):
    """Raised when the helper returns ``{"error": "..."}``."""

    def __init__(self, op: str, msg: str) -> None:
        super().__init__(f"helper op {op!r}: {msg}")
        self.op = op
        self.msg = msg


@dataclass
class ContractParams:
    """CKKS scheme parameters pinned per call."""

    ring_dim: int
    depth: int
    scaling_mod_size: int = 0
    scaling_factor: float = 0.0

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ring_dim": self.ring_dim, "depth": self.depth}
        if self.scaling_factor:
            out["scaling_factor"] = self.scaling_factor
        if self.scaling_mod_size:
            out["scaling_mod_size"] = self.scaling_mod_size
        return out


@dataclass
class KeyShare:
    """One participant's contribution to the chained N-party threshold keygen."""

    public_key: bytes
    secret_key_share: bytes
    lead: bool


@dataclass
class EvalKeyRound1Result:
    """Lead participant's round-1 output (bases everyone else extends)."""
    eval_mult_base: bytes
    eval_sum_base: bytes


@dataclass
class EvalKeyRound1ParticipantShare:
    """Non-lead participant's round-1 contribution."""
    eval_mult_switch_share: bytes
    eval_sum_share: bytes


@dataclass
class EvalKeyRound1Combined:
    """Output of combine_evalkey_round1 — orchestrator-side aggregation."""
    eval_mult_joined: bytes
    eval_sum_final: bytes


@dataclass
class EvalKeyFinal:
    """Output of combine_evalkey_round2 — the joint eval-mult + eval-sum keys."""
    eval_mult_final: bytes
    eval_sum_final: bytes


@dataclass
class EvalPolyParams:
    """Polynomial-evaluation configuration. Coefficients are in
    ascending order (coefficients[0] is the constant term).
    """

    coefficients: list[float] = field(default_factory=list)
    lower_bound: float = -1.0
    upper_bound: float = 1.0


class OpenFHEHelper:
    """Async wrapper around the helper subprocess."""

    def __init__(self, binary_path: str) -> None:
        self._binary_path = binary_path
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self._proc is not None:
            return
        # CKKS serialized public keys, eval-mult keys, and argmax mask
        # bundles can be tens to hundreds of MiB at production ring
        # dimensions. Bump the stream buffer well above the default
        # 64 KiB so readline returns whole envelopes.
        self._proc = await asyncio.create_subprocess_exec(
            self._binary_path,
            "--daemon",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            limit=512 * 1024 * 1024,
        )

    async def close(self) -> None:
        if self._proc is None:
            return
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            self._proc.kill()
        self._proc = None

    async def __aenter__(self) -> "OpenFHEHelper":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _call(self, op: str, params: ContractParams, **fields: Any) -> dict[str, Any]:
        if self._proc is None:
            raise RuntimeError("OpenFHEHelper.start() not called")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        body: dict[str, Any] = {"op": op, "params": params.to_json(), **fields}
        line = json.dumps(body) + "\n"

        async with self._lock:
            self._proc.stdin.write(line.encode("utf-8"))
            await self._proc.stdin.drain()
            raw = await self._proc.stdout.readline()
        if not raw:
            raise RuntimeError(f"helper op {op!r}: empty response (process died?)")
        envelope = json.loads(raw)
        if envelope.get("error"):
            raise HelperError(op, envelope["error"])
        return envelope.get("result") or {}

    # ── Existing protocol ops ─────────────────────────────────────────

    async def keygen_first(self, params: ContractParams) -> KeyShare:
        r = await self._call("keygen_first", params)
        return KeyShare(
            public_key=_b64dec(r["public_key"]),
            secret_key_share=_b64dec(r["secret_key_share"]),
            lead=bool(r.get("lead", False)),
        )

    async def keygen_next(self, params: ContractParams, prev_public_key: bytes) -> KeyShare:
        r = await self._call(
            "keygen_next", params,
            prev_public_key=_b64enc(prev_public_key),
        )
        return KeyShare(
            public_key=_b64dec(r["public_key"]),
            secret_key_share=_b64dec(r["secret_key_share"]),
            lead=bool(r.get("lead", False)),
        )

    async def encrypt(self, params: ContractParams, joint_public_key: bytes, values: list[float]) -> bytes:
        r = await self._call(
            "encrypt_profile", params,
            joint_public_key=_b64enc(joint_public_key),
            values=values,
        )
        return _b64dec(r["ciphertext"])

    async def partial_decrypt(self, params: ContractParams, ciphertext: bytes, secret_key_share: bytes, lead: bool) -> bytes:
        r = await self._call(
            "partial_decrypt", params,
            ciphertext=_b64enc(ciphertext),
            secret_key_share=_b64enc(secret_key_share),
            lead=lead,
        )
        return _b64dec(r["partial"])

    async def fuse_partials(self, params: ContractParams, partials: list[bytes], n_slots: int) -> list[float]:
        r = await self._call(
            "fuse_partials", params,
            partials=[_b64enc(p) for p in partials],
            n_slots=n_slots,
        )
        return list(r.get("values", []))

    # ── Eval-key rounds + combine (full N-party threshold keygen) ────

    async def evalkey_round1_lead(self, params: ContractParams, secret_key_share: bytes) -> EvalKeyRound1Result:
        r = await self._call("evalkey_round1_lead", params,
            secret_key_share=_b64enc(secret_key_share))
        return EvalKeyRound1Result(
            eval_mult_base=_b64dec(r["eval_mult_base"]),
            eval_sum_base=_b64dec(r["eval_sum_base"]),
        )

    async def evalkey_round1_participant(
        self, params: ContractParams,
        secret_key_share: bytes,
        eval_mult_base: bytes, eval_sum_base: bytes,
        own_public_key: bytes,
    ) -> EvalKeyRound1ParticipantShare:
        r = await self._call("evalkey_round1_participant", params,
            secret_key_share=_b64enc(secret_key_share),
            eval_mult_base=_b64enc(eval_mult_base),
            eval_sum_base=_b64enc(eval_sum_base),
            own_public_key=_b64enc(own_public_key))
        return EvalKeyRound1ParticipantShare(
            eval_mult_switch_share=_b64dec(r["eval_mult_share"]),
            eval_sum_share=_b64dec(r["eval_sum_share"]),
        )

    async def combine_evalkey_round1(
        self, params: ContractParams,
        public_keys: list[bytes],
        eval_mult_round1_shares: list[bytes],
        eval_sum_round1_shares: list[bytes],
    ) -> EvalKeyRound1Combined:
        r = await self._call("combine_evalkey_round1", params,
            public_keys=[_b64enc(b) for b in public_keys],
            eval_mult_round1_shares=[_b64enc(b) for b in eval_mult_round1_shares],
            eval_sum_round1_shares=[_b64enc(b) for b in eval_sum_round1_shares])
        return EvalKeyRound1Combined(
            eval_mult_joined=_b64dec(r["eval_mult_joined"]),
            eval_sum_final=_b64dec(r["eval_sum_final"]),
        )

    async def evalkey_round2_participant(
        self, params: ContractParams,
        secret_key_share: bytes,
        eval_mult_joined: bytes,
        final_public_key: bytes,
        lead: bool,
    ) -> bytes:
        """Returns the participant's round-2 eval-mult-final share."""
        r = await self._call("evalkey_round2_participant", params,
            secret_key_share=_b64enc(secret_key_share),
            eval_mult_joined=_b64enc(eval_mult_joined),
            final_public_key=_b64enc(final_public_key),
            lead=lead)
        return _b64dec(r["eval_mult_final_share"])

    async def combine_evalkey_round2(
        self, params: ContractParams,
        final_public_key: bytes,
        eval_mult_final_shares: list[bytes],
        eval_sum_final_key: bytes,
    ) -> EvalKeyFinal:
        r = await self._call("combine_evalkey_round2", params,
            final_public_key=_b64enc(final_public_key),
            eval_mult_final_shares=[_b64enc(b) for b in eval_mult_final_shares],
            eval_sum_final_key=_b64enc(eval_sum_final_key))
        return EvalKeyFinal(
            eval_mult_final=_b64dec(r["eval_mult_final"]),
            eval_sum_final=_b64dec(r["eval_sum_final"]),
        )

    async def run_full_keygen(self, params: ContractParams, n_participants: int) -> tuple[list[KeyShare], EvalKeyFinal]:
        """Convenience: run the complete N-party chained threshold keygen.

        Returns (per-participant shares including PK + secret share + lead
        flag, joint eval-mult/eval-sum key bundle). Useful for smoke
        drivers that need to set up a session-context end-to-end.
        """
        shares: list[KeyShare] = []
        first = await self.keygen_first(params)
        shares.append(first)
        for i in range(1, n_participants):
            nxt = await self.keygen_next(params, shares[-1].public_key)
            shares.append(nxt)
        final_pk = shares[-1].public_key

        lead = await self.evalkey_round1_lead(params, shares[0].secret_key_share)
        pks = [s.public_key for s in shares]
        mult_round1 = [lead.eval_mult_base]
        sum_round1 = [lead.eval_sum_base]
        for s in shares[1:]:
            r1 = await self.evalkey_round1_participant(
                params, s.secret_key_share, lead.eval_mult_base, lead.eval_sum_base, s.public_key,
            )
            mult_round1.append(r1.eval_mult_switch_share)
            sum_round1.append(r1.eval_sum_share)
        combined = await self.combine_evalkey_round1(params, pks, mult_round1, sum_round1)

        final_shares = []
        for s in shares:
            share = await self.evalkey_round2_participant(
                params, s.secret_key_share, combined.eval_mult_joined, final_pk, s.lead,
            )
            final_shares.append(share)
        final = await self.combine_evalkey_round2(params, final_pk, final_shares, combined.eval_sum_final)
        return shares, final

    # ── b-only rotation-key wire (CRS optimization) ──────────────────

    async def split_rot_share(
        self, params: ContractParams, eval_sum_share: bytes,
    ) -> tuple[bytes, bytes]:
        """Split a full eval-sum (rotation) key share into its shared a-vectors
        and per-party b-vectors. A participant uploads only b; the shared a is
        sent once per epoch or seeded from a CRS, and the combiner rebuilds the
        full share with reconstruct_rot_share. Returns (a, b)."""
        r = await self._call("split_rot_share", params,
            eval_sum_share=_b64enc(eval_sum_share))
        return _b64dec(r["eval_sum_share_a"]), _b64dec(r["eval_sum_share_b"])

    async def reconstruct_rot_share(
        self, params: ContractParams, a: bytes, b: bytes,
    ) -> bytes:
        """Rebuild a full eval-sum key share from the shared a-vectors and a
        party's b-vectors. Returns the full serialized share."""
        r = await self._call("reconstruct_rot_share", params,
            eval_sum_share_a=_b64enc(a),
            eval_sum_share_b=_b64enc(b))
        return _b64dec(r["eval_sum_share"])

    # ── Decomposable scoring primitives ──────────────────────────────

    async def eval_add(self, params: ContractParams, ct_a: bytes, ct_b: bytes) -> bytes:
        r = await self._call("eval_add", params,
            ciphertext_a=_b64enc(ct_a), ciphertext_b=_b64enc(ct_b))
        return _b64dec(r["ciphertext"])

    async def eval_sub(self, params: ContractParams, ct_a: bytes, ct_b: bytes) -> bytes:
        r = await self._call("eval_sub", params,
            ciphertext_a=_b64enc(ct_a), ciphertext_b=_b64enc(ct_b))
        return _b64dec(r["ciphertext"])

    async def eval_mult(self, params: ContractParams, eval_keys: bytes, ct_a: bytes, ct_b: bytes) -> bytes:
        r = await self._call("eval_mult", params,
            eval_keys=_b64enc(eval_keys),
            ciphertext_a=_b64enc(ct_a),
            ciphertext_b=_b64enc(ct_b))
        return _b64dec(r["ciphertext"])

    async def eval_const_mult(self, params: ContractParams, ct: bytes, scalar: float) -> bytes:
        r = await self._call("eval_const_mult", params,
            ciphertext=_b64enc(ct), scalar=scalar)
        return _b64dec(r["ciphertext"])

    async def eval_poly(self, params: ContractParams, eval_keys: bytes, ct: bytes, poly: EvalPolyParams) -> bytes:
        r = await self._call("eval_poly", params,
            eval_keys=_b64enc(eval_keys),
            ciphertext=_b64enc(ct),
            coefficients=poly.coefficients,
            poly_lower_bound=poly.lower_bound,
            poly_upper_bound=poly.upper_bound)
        return _b64dec(r["ciphertext"])

    async def argmax(
        self,
        params: ContractParams,
        eval_keys: bytes,
        ciphertexts: list[bytes],
        sharpening_poly: EvalPolyParams,
    ) -> list[bytes]:
        r = await self._call("argmax", params,
            eval_keys=_b64enc(eval_keys),
            ciphertexts=[_b64enc(ct) for ct in ciphertexts],
            coefficients=sharpening_poly.coefficients,
            poly_lower_bound=sharpening_poly.lower_bound,
            poly_upper_bound=sharpening_poly.upper_bound)
        return [_b64dec(c) for c in r.get("ciphertexts", [])]


def _b64enc(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _b64dec(s: str) -> bytes:
    if not s:
        return b""
    return base64.standard_b64decode(s)


# Built-in sharpening polynomials (mirrors helperclient/sharpening.go).

def sharpen_sign_degree3() -> EvalPolyParams:
    """Depth-1 cubic sign approximation: 1.5x − 0.5x³."""
    return EvalPolyParams(
        coefficients=[0, 1.5, 0, -0.5],
        lower_bound=-1.0, upper_bound=1.0,
    )


def sharpen_indicator_degree3() -> EvalPolyParams:
    """[0, 1]-mapped degree-3 sign approximation: 0.5 + 0.75x − 0.25x³.

    Useful as a sharpening polynomial for argmax (winner mask ≈ 1,
    loser mask ≈ 0).
    """
    return EvalPolyParams(
        coefficients=[0.5, 0.75, 0, -0.25],
        lower_bound=-1.0, upper_bound=1.0,
    )
