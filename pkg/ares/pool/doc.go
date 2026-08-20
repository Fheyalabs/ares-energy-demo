// SPDX-License-Identifier: Apache-2.0

// Package pool implements uniform-price double-auction clearing over
// encrypted step curves.
//
// Participants submit their offer curve sampled on a public price grid:
// a seller's curve holds its quantity at every grid price at or above its
// bid, a buyer's at every price at or below its limit. Because the curves
// are sampled rather than compared, aggregating them is pure addition —
// the server never compares individual bids. The only comparison in the
// circuit is a single sign test on the aggregate excess supply.
//
// The pure-Go layer (GridSpec, EncodeSupply, EncodeDemand, ClearPlaintext)
// has no OpenFHE dependency and is the reference oracle the homomorphic
// circuit is validated against. The circuit itself is in the openfhe-gated
// files.
package pool
