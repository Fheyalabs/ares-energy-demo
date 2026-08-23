// SPDX-License-Identifier: Apache-2.0

package phase

// AccumulateMessage stores payload under bucketKey indexed by sender. The
// stored shape is map[string][]byte (sender → payload bytes). Multiple
// submissions from the same sender overwrite (only the most recent is
// kept) — N-of-N protocols typically want one submission per
// participant.
//
// Safe for concurrent use across messages from different participants in
// the same session.
func AccumulateMessage(ctx *SessionContext, bucketKey, from string, payload []byte) {
	cp := append([]byte(nil), payload...)
	ctx.Update(bucketKey, func(current any) any {
		bucket, _ := current.(map[string][]byte)
		if bucket == nil {
			bucket = make(map[string][]byte)
		}
		bucket[from] = cp
		return bucket
	})
}

// MessageCount returns the number of distinct senders that have
// submitted under bucketKey.
func MessageCount(ctx *SessionContext, bucketKey string) int {
	v, ok := ctx.Get(bucketKey)
	if !ok {
		return 0
	}
	bucket, _ := v.(map[string][]byte)
	return len(bucket)
}

// AccumulatedMessages returns a shallow copy of the bucketKey map.
// Returns an empty (non-nil) map if no messages have been accumulated.
func AccumulatedMessages(ctx *SessionContext, bucketKey string) map[string][]byte {
	out := make(map[string][]byte)
	v, ok := ctx.Get(bucketKey)
	if !ok {
		return out
	}
	bucket, _ := v.(map[string][]byte)
	for k, val := range bucket {
		out[k] = val
	}
	return out
}

// QuorumReached returns true when MessageCount(ctx, bucketKey) >= n.
// The canonical "every participant has submitted" check used by
// CheckComplete hooks in N-of-N accumulator phases.
func QuorumReached(ctx *SessionContext, bucketKey string, n int) bool {
	return MessageCount(ctx, bucketKey) >= n
}
