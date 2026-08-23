// SPDX-License-Identifier: Apache-2.0

package helperclient

import "fmt"

func (c *Client) BFVKeygenFirst(params BFVContractParams) (KeyShare, error) {
	resp, err := c.call(Request{Op: "bfv_keygen_first", BFVParams: params})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

func (c *Client) BFVKeygenNext(params BFVContractParams, prevPublicKey []byte) (KeyShare, error) {
	resp, err := c.call(Request{
		Op:            "bfv_keygen_next",
		BFVParams:     params,
		PrevPublicKey: encodeB64(prevPublicKey),
	})
	if err != nil {
		return KeyShare{}, err
	}
	return decodeKeyShare(resp)
}

func (c *Client) BFVEncryptIntVector(params BFVContractParams, jointPublicKey []byte, values []int64) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "bfv_encrypt_int_vector",
		BFVParams:      params,
		JointPublicKey: encodeB64(jointPublicKey),
		IntValues:      values,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

func (c *Client) BFVEvalKeyRound1Lead(params BFVContractParams, secretKeyShare []byte) (EvalKeyRound1Result, error) {
	resp, err := c.call(Request{
		Op:             "bfv_evalkey_round1_lead",
		BFVParams:      params,
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

func (c *Client) BFVEvalKeyRound1Participant(
	params BFVContractParams,
	secretKeyShare, evalMultBase, evalSumBase, ownPublicKey []byte,
) (EvalKeyRound1ParticipantShare, error) {
	resp, err := c.call(Request{
		Op:             "bfv_evalkey_round1_participant",
		BFVParams:      params,
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

func (c *Client) BFVCombineEvalKeyRound1(
	params BFVContractParams,
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
		Op:                   "bfv_combine_evalkey_round1",
		BFVParams:            params,
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

func (c *Client) BFVEvalKeyRound2Participant(
	params BFVContractParams,
	secretKeyShare, evalMultJoined, finalPublicKey []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "bfv_evalkey_round2_participant",
		BFVParams:      params,
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

func (c *Client) BFVCombineEvalKeyRound2(
	params BFVContractParams,
	finalPublicKey []byte,
	finalShares [][]byte,
	evalSumFinal []byte,
) ([]byte, error) {
	encoded := make([]string, len(finalShares))
	for i, s := range finalShares {
		encoded[i] = encodeB64(s)
	}
	resp, err := c.call(Request{
		Op:                  "bfv_combine_evalkey_round2",
		BFVParams:           params,
		FinalPublicKey:      encodeB64(finalPublicKey),
		EvalMultFinalShares: encoded,
		EvalSumFinalKey:     encodeB64(evalSumFinal),
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.EvalMultFinal)
}

func (c *Client) BFVKeygenChain(params BFVContractParams, n int) (*EvalKeyBundle, error) {
	if n < 2 {
		return nil, fmt.Errorf("BFVKeygenChain: n must be >= 2, got %d", n)
	}

	shares := make([]KeyShare, n)
	first, err := c.BFVKeygenFirst(params)
	if err != nil {
		return nil, fmt.Errorf("BFVKeygenChain: slot 0 bfv_keygen_first: %w", err)
	}
	shares[0] = first
	for slot := 1; slot < n; slot++ {
		next, err := c.BFVKeygenNext(params, shares[slot-1].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("BFVKeygenChain: slot %d bfv_keygen_next: %w", slot, err)
		}
		shares[slot] = next
	}
	finalPublicKey := shares[n-1].PublicKey

	r1Lead, err := c.BFVEvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return nil, fmt.Errorf("BFVKeygenChain: bfv_evalkey_round1_lead: %w", err)
	}
	pks := make([][]byte, n)
	multShares := make([][]byte, n)
	sumShares := make([][]byte, n)
	pks[0], multShares[0], sumShares[0] = shares[0].PublicKey, r1Lead.EvalMultBase, r1Lead.EvalSumBase
	for slot := 1; slot < n; slot++ {
		ps, err := c.BFVEvalKeyRound1Participant(params, shares[slot].SecretKeyShare, r1Lead.EvalMultBase, r1Lead.EvalSumBase, shares[slot].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("BFVKeygenChain: slot %d bfv_evalkey_round1_participant: %w", slot, err)
		}
		pks[slot], multShares[slot], sumShares[slot] = shares[slot].PublicKey, ps.EvalMultShare, ps.EvalSumShare
	}
	r1Combined, err := c.BFVCombineEvalKeyRound1(params, pks, multShares, sumShares)
	if err != nil {
		return nil, fmt.Errorf("BFVKeygenChain: bfv_combine_evalkey_round1: %w", err)
	}

	r2Shares := make([][]byte, n)
	for slot := 0; slot < n; slot++ {
		final, err := c.BFVEvalKeyRound2Participant(params, shares[slot].SecretKeyShare, r1Combined.EvalMultJoined, finalPublicKey, slot == 0)
		if err != nil {
			return nil, fmt.Errorf("BFVKeygenChain: slot %d bfv_evalkey_round2_participant: %w", slot, err)
		}
		r2Shares[slot] = final
	}
	evalKeys, err := c.BFVCombineEvalKeyRound2(params, finalPublicKey, r2Shares, r1Combined.EvalSumFinal)
	if err != nil {
		return nil, fmt.Errorf("BFVKeygenChain: bfv_combine_evalkey_round2: %w", err)
	}

	return &EvalKeyBundle{
		PublicKey:   finalPublicKey,
		EvalKeys:    evalKeys,
		EvalSumKeys: r1Combined.EvalSumFinal,
		KeyShares:   shares,
	}, nil
}

func (c *Client) BFVEvalProductSum(params BFVContractParams, evalMultKey, evalSumKey, leftCiphertext, rightCiphertext []byte, nSlots int) ([]byte, error) {
	resp, err := c.call(Request{
		Op:              "bfv_eval_product_sum",
		BFVParams:       params,
		EvalKeys:        encodeB64(evalMultKey),
		EvalSumFinalKey: encodeB64(evalSumKey),
		CiphertextA:     encodeB64(leftCiphertext),
		CiphertextB:     encodeB64(rightCiphertext),
		NSlots:          nSlots,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

func (c *Client) BFVPartialDecrypt(
	params BFVContractParams,
	ciphertext, secretKeyShare []byte,
	lead bool,
) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "bfv_partial_decrypt",
		BFVParams:      params,
		Ciphertext:     encodeB64(ciphertext),
		SecretKeyShare: encodeB64(secretKeyShare),
		Lead:           lead,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Partial)
}

func (c *Client) BFVFusePartials(params BFVContractParams, partials [][]byte, nSlots int) ([]int64, error) {
	enc := make([]string, len(partials))
	for i, p := range partials {
		enc[i] = encodeB64(p)
	}
	resp, err := c.call(Request{
		Op:        "bfv_fuse_partials_int",
		BFVParams: params,
		Partials:  enc,
		NSlots:    nSlots,
	})
	if err != nil {
		return nil, err
	}
	return resp.IntValues, nil
}
