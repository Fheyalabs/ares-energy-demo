// SPDX-License-Identifier: Apache-2.0

package defaults

import (
	"reflect"
	"testing"
)

func TestPhase0aThresholdKeygen_ConsumesAllKeygenMessages(t *testing.T) {
	got := NewPhase0aThresholdKeygen().ConsumedMessageTypes()
	want := []string{"keygen.share", "keygen.eval_round1", "keygen.eval_share"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConsumedMessageTypes() = %v, want %v", got, want)
	}
}
