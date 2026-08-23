// SPDX-License-Identifier: Apache-2.0

package helperclient

import "fmt"

// Protocol ops: the helper RPCs the framework smokes use for
// threshold keygen, encryption, and partial-decryption.

// KeyShare is the result of one participant's contribution to the
// chained N-party threshold keygen. PublicKey is the (running) joint
// public key after this contribution; SecretKeyShare is this
// participant's share, retained client-side and used later in
// PartialDecrypt. Lead is true for the first participant.
type KeyShare struct {
	PublicKey      []byte
	SecretKeyShare []byte
	Lead           bool
}

// KeygenFirst is the first participant's contribution to keygen.
// Returns the bootstrap joint key plus the participant's share.
func (c *Client) KeygenFirst(params ContractParams) (KeyShare, error) {
	resp, err := c.call(Request{Op: "keygen_first", Params: params})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

// KeygenNext extends the joint key with the next participant's share.
// prevPublicKey is the joint key emitted by the previous participant.
func (c *Client) KeygenNext(params ContractParams, prevPublicKey []byte) (KeyShare, error) {
	resp, err := c.call(Request{
		Op:            "keygen_next",
		Params:        params,
		PrevPublicKey: encodeB64(prevPublicKey),
	})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

// EncryptProfile encrypts a float-valued vector under the joint
// public key. Used by participants to seal their inputs (bid amount,
// rating, profile vector, etc.).
func (c *Client) EncryptProfile(params ContractParams, jointPublicKey []byte, values []float64) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "encrypt_profile",
		Params:         params,
		JointPublicKey: encodeB64(jointPublicKey),
		Values:         values,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalKeyRound1Result is the lead's round-1 output: the bases that
// subsequent participants extend in round 1.
type EvalKeyRound1Result struct {
	EvalMultBase []byte
	EvalSumBase  []byte
}

// EvalKeyRound1Lead is the lead participant's round-1 contribution.
func (c *Client) EvalKeyRound1Lead(params ContractParams, secretKeyShare []byte) (EvalKeyRound1Result, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round1_lead",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
	})
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	multBase, err := decodeB64(resp.EvalMultBase)
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	sumBase, err := decodeB64(resp.EvalSumBase)
	if err != nil {
		return EvalKeyRound1Result{}, err
	}
	return EvalKeyRound1Result{EvalMultBase: multBase, EvalSumBase: sumBase}, nil
}

// EvalKeyRound1ParticipantShare is the per-participant output of
// round 1 (the share that gets fused into the joint eval-mult and
// eval-sum keys).
type EvalKeyRound1ParticipantShare struct {
	EvalMultShare []byte
	EvalSumShare  []byte
}

// EvalKeyRound1Participant is a non-lead participant's round-1
// contribution.
func (c *Client) EvalKeyRound1Participant(
	params ContractParams,
	secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte,
) (EvalKeyRound1ParticipantShare, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round1_participant",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
		EvalMultBase:   encodeB64(evalMultBase),
		EvalSumBase:    encodeB64(evalSumBase),
		OwnPublicKey:   encodeB64(ownPublicKey),
	})
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	multShare, err := decodeB64(resp.EvalMultShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	sumShare, err := decodeB64(resp.EvalSumShare)
	if err != nil {
		return EvalKeyRound1ParticipantShare{}, err
	}
	return EvalKeyRound1ParticipantShare{EvalMultShare: multShare, EvalSumShare: sumShare}, nil
}

// EvalKeyRound2Participant is one participant's round-2 contribution.
func (c *Client) EvalKeyRound2Participant(
	params ContractParams,
	secretKeyShare, evalMultJoined, finalPublicKey []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "evalkey_round2_participant",
		Params:         params,
		SecretKeyShare: encodeB64(secretKeyShare),
		EvalMultJoined: encodeB64(evalMultJoined),
		FinalPublicKey: encodeB64(finalPublicKey),
		Lead:           lead,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.EvalMultFinalShare)
}

// PartialDecrypt produces one participant's partial decryption of a
// ciphertext.
func (c *Client) PartialDecrypt(
	params ContractParams,
	ciphertext, secretKeyShare []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "partial_decrypt",
		Params:         params,
		Ciphertext:     encodeB64(ciphertext),
		SecretKeyShare: encodeB64(secretKeyShare),
		Lead:           lead,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Partial)
}

// CombineEvalKeyRound1Result is the combined output of the eval
// round-1 fuse step. EvalMultJoined feeds round 2; EvalSumFinal is
// the completed eval-sum key used as input to round 2's combine.
type CombineEvalKeyRound1Result struct {
	EvalMultJoined []byte
	EvalSumFinal   []byte
}

// CombineEvalKeyRound1 fuses all N participants' eval round-1 shares.
func (c *Client) CombineEvalKeyRound1(
	params ContractParams,
	pks [][]byte,
	multShares [][]byte,
	sumShares [][]byte,
) (*CombineEvalKeyRound1Result, error) {
	encPKs := make([]string, len(pks))
	for i, pk := range pks {
		encPKs[i] = encodeB64(pk)
	}
	encMult := make([]string, len(multShares))
	for i, s := range multShares {
		encMult[i] = encodeB64(s)
	}
	encSum := make([]string, len(sumShares))
	for i, s := range sumShares {
		encSum[i] = encodeB64(s)
	}
	resp, err := c.call(Request{
		Op:                   "combine_evalkey_round1",
		Params:               params,
		PublicKeys:           encPKs,
		EvalMultRound1Shares: encMult,
		EvalSumRound1Shares:  encSum,
	})
	if err != nil {
		return nil, err
	}
	joined, err := decodeB64(resp.EvalMultJoined)
	if err != nil {
		return nil, err
	}
	sumFinal, err := decodeB64(resp.EvalSumFinal)
	if err != nil {
		return nil, err
	}
	return &CombineEvalKeyRound1Result{EvalMultJoined: joined, EvalSumFinal: sumFinal}, nil
}

// CombineEvalKeyRound2 fuses every participant's round-2 final eval
// share into the joint eval-mult key. finalPublicKey is the joint
// public key after all N keygen contributions. evalSumFinal is the
// completed eval-sum key from CombineEvalKeyRound1.
func (c *Client) CombineEvalKeyRound2(
	params ContractParams,
	finalPublicKey []byte,
	finalShares [][]byte,
	evalSumFinal []byte,
) ([]byte, error) {
	encoded := make([]string, len(finalShares))
	for i, s := range finalShares {
		encoded[i] = encodeB64(s)
	}
	resp, err := c.call(Request{
		Op:                  "combine_evalkey_round2",
		Params:              params,
		FinalPublicKey:      encodeB64(finalPublicKey),
		EvalMultFinalShares: encoded,
		EvalSumFinalKey:     encodeB64(evalSumFinal),
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.EvalMultFinal)
}

// EvalKeyBundle is the output of a complete N-party distributed keygen
// chain. It contains everything downstream phases need to encrypt,
// score, and threshold-decrypt.
type EvalKeyBundle struct {
	PublicKey   []byte
	EvalKeys    []byte
	EvalSumKeys []byte
	KeyShares   []KeyShare // one per participant, ordered by slot
}

// KeygenChain runs the full N-party distributed CKKS keygen in one
// process. It chains KeygenFirst / KeygenNext to build the collective
// public key, then runs the two eval-key rounds to produce joint eval
// keys. Designed for single-machine smoke tests where all N simulated
// participants run in the same process.
//
// The returned EvalKeyBundle.PublicKey is the final collective public
// key after all N contributions. Bundle.EvalKeys is the joint eval-key
// blob suitable for passing to Argmax, EvalPoly, etc.
// Bundle.KeyShares[i] is participant i's individual key share (PublicKey
// after their contribution + their SecretKeyShare for partial decrypt).
func (c *Client) KeygenChain(params ContractParams, n int) (*EvalKeyBundle, error) {
	if n < 2 {
		return nil, fmt.Errorf("KeygenChain: n must be >= 2, got %d", n)
	}

	shares := make([]KeyShare, n)

	// --- keygen chain ---
	first, err := c.KeygenFirst(params)
	if err != nil {
		return nil, fmt.Errorf("KeygenChain: slot 0 keygen_first: %w", err)
	}
	shares[0] = first

	for slot := 1; slot < n; slot++ {
		next, err := c.KeygenNext(params, shares[slot-1].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("KeygenChain: slot %d keygen_next: %w", slot, err)
		}
		shares[slot] = next
	}
	finalPublicKey := shares[n-1].PublicKey

	// --- eval round 1 ---
	r1Lead, err := c.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, fmt.Errorf("KeygenChain: evalkey_round1_lead: %w", err)
	}

	// Collect all N slots' round-1 shares. Slot 0 contributes the
	// lead's bases; slots 1..N-1 contribute their participant shares.
	pks := make([][]byte, n)
	multShares := make([][]byte, n)
	sumShares := make([][]byte, n)
	pks[0] = shares[0].PublicKey
	multShares[0] = r1Lead.EvalMultBase
	sumShares[0] = r1Lead.EvalSumBase

	for slot := 1; slot < n; slot++ {
		ps, err := c.EvalKeyRound1Participant(params,
			shares[slot].SecretKeyShare,
			r1Lead.EvalMultBase, r1Lead.EvalSumBase,
			shares[slot].PublicKey,
		)
		if err != nil {
			return nil, fmt.Errorf("KeygenChain: slot %d evalkey_round1_participant: %w", slot, err)
		}
		pks[slot] = shares[slot].PublicKey
		multShares[slot] = ps.EvalMultShare
		sumShares[slot] = ps.EvalSumShare
	}

	r1Combined, err := c.CombineEvalKeyRound1(params, pks, multShares, sumShares)
	if err != nil {
		return nil, fmt.Errorf("KeygenChain: combine_evalkey_round1: %w", err)
	}

	// --- eval round 2 ---
	r2Shares := make([][]byte, n)
	for slot := 0; slot < n; slot++ {
		final, err := c.EvalKeyRound2Participant(params,
			shares[slot].SecretKeyShare,
			r1Combined.EvalMultJoined, finalPublicKey,
			slot == 0,
		)
		if err != nil {
			return nil, fmt.Errorf("KeygenChain: slot %d evalkey_round2_participant: %w", slot, err)
		}
		r2Shares[slot] = final
	}

	evalKeys, err := c.CombineEvalKeyRound2(params, finalPublicKey, r2Shares, r1Combined.EvalSumFinal)
	if err != nil {
		return nil, fmt.Errorf("KeygenChain: combine_evalkey_round2: %w", err)
	}

	return &EvalKeyBundle{
		PublicKey:   finalPublicKey,
		EvalKeys:    evalKeys,
		EvalSumKeys: r1Combined.EvalSumFinal,
		KeyShares:   shares,
	}, nil
}

// FusePartials combines participants' partial decryptions into the
// cleartext slot values.
func (c *Client) FusePartials(params ContractParams, partials [][]byte, nSlots int) ([]float64, error) {
	enc := make([]string, len(partials))
	for i, p := range partials {
		enc[i] = encodeB64(p)
	}
	resp, err := c.call(Request{
		Op:       "fuse_partials",
		Params:   params,
		Partials: enc,
		NSlots:   nSlots,
	})
	if err != nil {
		return nil, err
	}
	return resp.Values, nil
}

func decodeKeyShare(resp *Response) (KeyShare, error) {
	pk, err := decodeB64(resp.PublicKey)
	if err != nil {
		return KeyShare{}, err
	}
	sk, err := decodeB64(resp.SecretKeyShare)
	if err != nil {
		return KeyShare{}, err
	}
	lead := false
	if resp.Lead != nil {
		lead = *resp.Lead
	}
	return KeyShare{PublicKey: pk, SecretKeyShare: sk, Lead: lead}, nil
}

// SupportedOpenFHEVersionPrefix is the OpenFHE major.minor line the
// framework is tested against. Helpers reporting a different
// major/minor prefix will trigger a startup warning. Patch-level
// differences are allowed.
const SupportedOpenFHEVersionPrefix = "v1.5."

// Version asks the helper subprocess what OpenFHE library version it
// was linked against. Used by Start to surface version mismatches at
// daemon startup.
func (c *Client) Version() (string, error) {
	res, err := c.call(Request{Op: "version"})
	if err != nil {
		return "", err
	}
	return res.Version, nil
}
