// SPDX-License-Identifier: Apache-2.0

// Package anon provides composable onion-shuffle phases that give a
// ranking session inter-participant slot anonymity: no participant
// learns which anonymized slot belongs to which other participant.
// PhaseGShuffle sequences the onion-peel rounds; PhaseGVerify
// assembles the slot list and binds each submission to the
// session-rooted lineage DAG. Slot submissions are signed by an
// ephemeral per-slot key (see Participant), so the binding gives
// tamper-evidence without revealing the slot->identity mapping to
// other participants. The onion cryptography lives in
// github.com/Fheyalabs/ares-core/pkg/ares/onion; the collusion bound
// is documented there.
package anon
