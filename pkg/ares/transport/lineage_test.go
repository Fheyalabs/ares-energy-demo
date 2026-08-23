// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"encoding/json"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func TestWSMessage_LineageRoundTrip_FullDAGNodeInline(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("payload"), nil, signer)

	msg := transport.WSMessage{
		Version:   transport.WireProtocolVersionLineage,
		Type:      "test.frame",
		SessionID: "s",
		Seq:       1,
		Payload:   json.RawMessage(`"payload"`),
		Lineage:   &node,
	}

	wire, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got transport.WSMessage
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Version != transport.WireProtocolVersionLineage {
		t.Errorf("Version = %q, want %q", got.Version, transport.WireProtocolVersionLineage)
	}
	if got.Lineage == nil {
		t.Fatal("Lineage round-tripped as nil")
	}
	if got.Lineage.Hash != node.Hash {
		t.Errorf("Lineage.Hash = %x, want %x", got.Lineage.Hash, node.Hash)
	}
	if got.Lineage.Role != "r" {
		t.Errorf("Lineage.Role = %q, want %q", got.Lineage.Role, "r")
	}
}

func TestWSMessage_BackwardCompat_NoLineageField(t *testing.T) {
	// A v1 frame (no Lineage field) must still round-trip cleanly.
	// Compose(...)-built pipelines emit these.
	msg := transport.WSMessage{
		Version:   transport.WireProtocolVersion,
		Type:      "legacy.frame",
		SessionID: "s",
		Payload:   json.RawMessage(`"p"`),
	}
	wire, _ := json.Marshal(msg)
	var got transport.WSMessage
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Lineage != nil {
		t.Errorf("v1 frame round-tripped with non-nil Lineage")
	}
	if got.Version != transport.WireProtocolVersion {
		t.Errorf("Version = %q, want %q", got.Version, transport.WireProtocolVersion)
	}
}

func TestValidateInboundMessage_RejectsV2FrameMissingLineage(t *testing.T) {
	msg := transport.WSMessage{
		Version:   transport.WireProtocolVersionLineage,
		Type:      "test.frame",
		SessionID: "s",
		Payload:   json.RawMessage(`"p"`),
		Lineage:   nil,
	}
	err := transport.ValidateInboundMessage(msg)
	if err == nil {
		t.Fatal("expected validator to reject v2 frame missing Lineage")
	}
}

func TestValidateInboundMessage_AcceptsV1FrameWithoutLineage(t *testing.T) {
	msg := transport.WSMessage{
		Version:   transport.WireProtocolVersion,
		Type:      "legacy.frame",
		SessionID: "s",
		Payload:   json.RawMessage(`"p"`),
	}
	if err := transport.ValidateInboundMessage(msg); err != nil {
		t.Errorf("v1 frame rejected: %v", err)
	}
}

func TestValidateInboundMessage_AcceptsEmptyVersionAsV1(t *testing.T) {
	// Pre-v0.3 clients leave Version empty; validator treats as v1.
	msg := transport.WSMessage{
		Type:      "legacy.frame",
		SessionID: "s",
		Payload:   json.RawMessage(`"p"`),
	}
	if err := transport.ValidateInboundMessage(msg); err != nil {
		t.Errorf("empty-version frame rejected: %v", err)
	}
}

func TestValidateInboundMessage_AcceptsV2FrameWithLineage(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("payload"), nil, signer)
	msg := transport.WSMessage{
		Version:   transport.WireProtocolVersionLineage,
		Type:      "test.frame",
		SessionID: "s",
		Payload:   json.RawMessage(`"payload"`),
		Lineage:   &node,
	}
	if err := transport.ValidateInboundMessage(msg); err != nil {
		t.Errorf("v2 frame with Lineage rejected: %v", err)
	}
}

func TestValidateInboundMessage_RejectsUnknownVersion(t *testing.T) {
	msg := transport.WSMessage{
		Version:   "99",
		Type:      "future.frame",
		SessionID: "s",
	}
	err := transport.ValidateInboundMessage(msg)
	if err == nil {
		t.Fatal("expected validator to reject unknown protocol version")
	}
}
