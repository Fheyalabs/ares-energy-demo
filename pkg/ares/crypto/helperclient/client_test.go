// SPDX-License-Identifier: Apache-2.0

package helperclient

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestSharpenSignDegree3_Shape(t *testing.T) {
	p := SharpenSignDegree3()
	if len(p.Coefficients) != 4 {
		t.Errorf("degree-3 should have 4 coefficients, got %d", len(p.Coefficients))
	}
	// Odd polynomial: even-indexed coefficients are zero.
	for i := 0; i < len(p.Coefficients); i += 2 {
		if p.Coefficients[i] != 0 {
			t.Errorf("coeff[%d] = %v, want 0 (odd polynomial)", i, p.Coefficients[i])
		}
	}
	if p.LowerBound != -1.0 || p.UpperBound != 1.0 {
		t.Errorf("domain = [%v,%v], want [-1,1]", p.LowerBound, p.UpperBound)
	}
}

func TestSharpenSignDegree9_OddOnly(t *testing.T) {
	p := SharpenSignDegree9()
	if len(p.Coefficients) != 10 {
		t.Errorf("degree-9 should have 10 coefficients, got %d", len(p.Coefficients))
	}
	for i := 0; i < len(p.Coefficients); i += 2 {
		if p.Coefficients[i] != 0 {
			t.Errorf("coeff[%d] = %v, want 0 (odd polynomial)", i, p.Coefficients[i])
		}
	}
}

func TestSharpenChebyshev_NilCoeffs(t *testing.T) {
	p := SharpenChebyshev(-2.0, 2.0, 9)
	if p.Coefficients != nil {
		t.Errorf("Chebyshev sentinel should leave Coefficients nil; got %v", p.Coefficients)
	}
	if p.LowerBound != -2.0 || p.UpperBound != 2.0 {
		t.Errorf("domain = [%v,%v], want [-2,2]", p.LowerBound, p.UpperBound)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := []byte{1, 2, 3, 0xff, 0x00, 0x42}
	encoded := encodeB64(original)
	decoded, err := decodeB64(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("roundtrip mismatch: %v vs %v", original, decoded)
	}
}

func TestDecodeB64_Empty(t *testing.T) {
	b, err := decodeB64("")
	if err != nil {
		t.Errorf("empty decode should be nil-no-error, got %v", err)
	}
	if b != nil {
		t.Errorf("empty decode should produce nil bytes, got %v", b)
	}
}

func TestDecodeB64_Invalid(t *testing.T) {
	_, err := decodeB64("not-valid-base64!@#")
	if err == nil {
		t.Errorf("expected error decoding invalid base64")
	}
}

func TestHelperError_Format(t *testing.T) {
	e := &HelperError{Op: "argmax", Msg: "depth too low"}
	want := `helper op "argmax": depth too low`
	if e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
}

func TestContractParamsDefaultSchemeIsCKKS(t *testing.T) {
	var req Request
	if err := json.Unmarshal([]byte(`{"op":"keygen_first","params":{"ring_dim":32768,"depth":16}}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := req.Params.EffectiveScheme(); got != SchemeCKKS {
		t.Fatalf("EffectiveScheme = %q, want %q", got, SchemeCKKS)
	}
}

func TestBFVRequestJSONShape(t *testing.T) {
	req := Request{
		Op: "bfv_encrypt_int_vector",
		BFVParams: BFVContractParams{
			RingDim:             32768,
			MultiplicativeDepth: 20,
			PlaintextModulus:    65537,
			BatchSize:           128,
		},
		JointPublicKey: encodeB64([]byte("pk")),
		IntValues:      []int64{-63, 0, 63},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"op":"bfv_encrypt_int_vector"`,
		`"bfv_params"`,
		`"plaintext_modulus":65537`,
		`"int_values":[-63,0,63]`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("encoded request %s does not contain %s", s, want)
		}
	}
}

func TestBFVEncryptIntVectorSendsBFVOp(t *testing.T) {
	params := BFVContractParams{
		RingDim:             32768,
		MultiplicativeDepth: 20,
		PlaintextModulus:    65537,
		BatchSize:           128,
	}
	client := recordingClient(t, func(req Request) Response {
		if req.Op != "bfv_encrypt_int_vector" {
			t.Fatalf("Op = %q", req.Op)
		}
		if req.BFVParams != params {
			t.Fatalf("BFVParams = %+v, want %+v", req.BFVParams, params)
		}
		if string(mustDecode(t, req.JointPublicKey)) != "pk" {
			t.Fatalf("JointPublicKey = %q", req.JointPublicKey)
		}
		if got := req.IntValues; len(got) != 3 || got[0] != -63 || got[2] != 63 {
			t.Fatalf("IntValues = %+v", got)
		}
		return Response{Ciphertext: encodeB64([]byte("ct"))}
	})

	got, err := client.BFVEncryptIntVector(params, []byte("pk"), []int64{-63, 0, 63})
	if err != nil {
		t.Fatalf("BFVEncryptIntVector: %v", err)
	}
	if string(got) != "ct" {
		t.Fatalf("ciphertext = %q, want ct", string(got))
	}
}

func recordingClient(t *testing.T, handle func(Request) Response) *Client {
	t.Helper()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() {
		defer reqR.Close()
		defer respW.Close()
		var req Request
		if err := json.NewDecoder(reqR).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		env := envelope{Result: &[]Response{handle(req)}[0]}
		if err := json.NewEncoder(respW).Encode(env); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}()
	return &Client{
		stdin:  reqW,
		stdout: bufio.NewReader(respR),
		enc:    json.NewEncoder(reqW),
		dec:    json.NewDecoder(respR),
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	out, err := decodeB64(s)
	if err != nil {
		t.Fatalf("decodeB64: %v", err)
	}
	return out
}
