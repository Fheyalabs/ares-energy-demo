// SPDX-License-Identifier: Apache-2.0

// Package sign provides a pluggable signature primitive used by the
// lineage package and available to applications for any signed-message
// pattern.
//
// The framework ships Ed25519Signer as the default implementation
// (crypto/ed25519 from stdlib). Applications can substitute alternative
// schemes (HSM-backed, post-quantum) by implementing the Signer
// interface and passing the instance via phase.ComposeWith options.
package sign
