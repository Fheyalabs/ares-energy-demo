// SPDX-License-Identifier: Apache-2.0

package helperclient

type Scheme string

const (
	SchemeCKKS Scheme = "ckks"
	SchemeBFV  Scheme = "bfv"
)

// ContractParams pins the CKKS scheme parameters for one call. The
// helper recreates the CryptoContext from these on every op (until a
// persistent-session protocol lands).
type ContractParams struct {
	Scheme         Scheme  `json:"scheme,omitempty"`
	RingDim        uint32  `json:"ring_dim"`
	ScalingFactor  float64 `json:"scaling_factor,omitempty"`
	ScalingModSize int     `json:"scaling_mod_size,omitempty"`
	Depth          uint32  `json:"depth"`
}

func (p ContractParams) EffectiveScheme() Scheme {
	if p.Scheme == "" {
		return SchemeCKKS
	}
	return p.Scheme
}

// BFVContractParams pins integer BFV parameters. It is intentionally
// separate from ContractParams so CKKS float-slot calls and BFV
// packed-integer calls cannot silently share incompatible fields.
type BFVContractParams struct {
	RingDim             uint32 `json:"ring_dim"`
	MultiplicativeDepth uint32 `json:"multiplicative_depth"`
	PlaintextModulus    uint64 `json:"plaintext_modulus"`
	BatchSize           int    `json:"batch_size,omitempty"`
}

// Request is the union of every helper op's input. Fields are populated
// per-op; the helper dispatches on Op.
type Request struct {
	Op        string            `json:"op"`
	Params    ContractParams    `json:"params"`
	BFVParams BFVContractParams `json:"bfv_params,omitempty"`

	// Existing protocol-op fields.
	PrevPublicKey  string    `json:"prev_public_key,omitempty"`
	JointPublicKey string    `json:"joint_public_key,omitempty"`
	OwnPublicKey   string    `json:"own_public_key,omitempty"`
	FinalPublicKey string    `json:"final_public_key,omitempty"`
	EvalMultBase   string    `json:"eval_mult_base,omitempty"`
	EvalSumBase    string    `json:"eval_sum_base,omitempty"`
	EvalMultJoined string    `json:"eval_mult_joined,omitempty"`
	Values         []float64 `json:"values,omitempty"`
	IntValues      []int64   `json:"int_values,omitempty"`
	Ciphertext     string    `json:"ciphertext,omitempty"`
	SecretKeyShare string    `json:"secret_key_share,omitempty"`
	Lead           bool      `json:"lead,omitempty"`
	Partials       []string  `json:"partials,omitempty"`
	NSlots         int       `json:"n_slots,omitempty"`

	// Decomposable scoring primitives.

	// EvalKeys is the base64-serialized joint evaluation-key bundle
	// (the result of the keygen round-2 fusion). Every arithmetic op
	// that involves multiplication or rotation needs it.
	EvalKeys string `json:"eval_keys,omitempty"`

	// CiphertextA / CiphertextB are operand ciphertexts for binary
	// arithmetic ops (eval_add, eval_mult, eval_sub).
	CiphertextA string `json:"ciphertext_a,omitempty"`
	CiphertextB string `json:"ciphertext_b,omitempty"`

	// Scalar is the constant operand for eval_const_mult.
	Scalar float64 `json:"scalar,omitempty"`

	// Coefficients carries the polynomial in coefficient-ascending
	// order for eval_poly and as the sharpening polynomial for
	// argmax. coeffs[0] is the constant term.
	Coefficients []float64 `json:"coefficients,omitempty"`

	// PolyLowerBound / PolyUpperBound are the domain of the
	// polynomial input for eval_poly. CKKS polynomial evaluation
	// expects the input to be in a known range; these tell the
	// underlying call how to scale.
	PolyLowerBound float64 `json:"poly_lower_bound,omitempty"`
	PolyUpperBound float64 `json:"poly_upper_bound,omitempty"`

	// Ciphertexts is the multi-operand list for argmax. Each element
	// is the ciphertext for one candidate's score.
	Ciphertexts []string `json:"ciphertexts,omitempty"`

	// Combine-round-1 / combine-round-2 fields (server-side keygen).
	PublicKeys           []string `json:"public_keys,omitempty"`
	EvalMultRound1Shares []string `json:"eval_mult_round1_shares,omitempty"`
	EvalSumRound1Shares  []string `json:"eval_sum_round1_shares,omitempty"`
	EvalMultFinalShares  []string `json:"eval_mult_final_shares,omitempty"`
	EvalSumFinalKey      string   `json:"eval_sum_final_key,omitempty"`
}

// Response is the union of every helper op's output. Same per-op
// population convention as Request.
type Response struct {
	// Protocol-op fields.
	PublicKey          string    `json:"public_key,omitempty"`
	SecretKeyShare     string    `json:"secret_key_share,omitempty"`
	Lead               *bool     `json:"lead,omitempty"`
	Ciphertext         string    `json:"ciphertext,omitempty"`
	Partial            string    `json:"partial,omitempty"`
	Values             []float64 `json:"values,omitempty"`
	IntValues          []int64   `json:"int_values,omitempty"`
	EvalMultBase       string    `json:"eval_mult_base,omitempty"`
	EvalSumBase        string    `json:"eval_sum_base,omitempty"`
	EvalMultShare      string    `json:"eval_mult_share,omitempty"`
	EvalSumShare       string    `json:"eval_sum_share,omitempty"`
	EvalMultJoined     string    `json:"eval_mult_joined,omitempty"`
	EvalMultFinalShare string    `json:"eval_mult_final_share,omitempty"`
	EvalSumFinal       string    `json:"eval_sum_final,omitempty"`
	EvalMultFinal      string    `json:"eval_mult_final,omitempty"`

	// Decomposable scoring primitive outputs.

	// Ciphertexts is the list output for ops like argmax that emit
	// per-candidate mask ciphertexts.
	Ciphertexts []string `json:"ciphertexts,omitempty"`

	// Version is the linked OpenFHE library version (e.g. "v1.5.1").
	// Populated only by the `version` op.
	Version string `json:"version,omitempty"`
}

// envelope is the on-the-wire daemon-mode message: exactly one of
// Result or Error is non-empty.
type envelope struct {
	Result *Response `json:"result,omitempty"`
	Error  string    `json:"error,omitempty"`
}
