// SPDX-License-Identifier: Apache-2.0

// Package main runs a browser demo of the uniform-price pool: each tab is
// a participant, picks a side, and submits a sealed offer curve.
//
// The market layer here is plaintext and public by design: the price
// grid, the reference feeds and the two synthetic grid participants are
// all published. Only participant offer curves are sealed.
package main

import "math"

// DayPrices holds real DE-LU day-ahead wholesale prices in ct/kWh for
// 2024-05-12, one value per hour.
//
// Source: energy-charts.info (Fraunhofer ISE), republishing SMARD /
// Bundesnetzagentur market data, CC-BY 4.0.
//
// This day is the demo's centrepiece: the price collapses to -13.54 ct at
// 13:00, when solar output peaks. Generation is worth *less than nothing*
// on the wholesale market at exactly the moment there is most of it.
var DayPrices = []float64{
	6.55, 5.45, 4.45, 4.12, 4.63, 4.35, 1.76, 0.48,
	0.24, -0.28, -2.50, -6.96, -10.01, -13.54, -13.29, -8.51,
	-3.00, -0.13, 2.25, 6.79, 7.57, 5.83, 4.46, 3.56,
}

// RetailEnergyRate is the flat-tariff buyer's avoided energy cost in
// ct/kWh: the retail price less the grid fees, levies and taxes that
// apply either way and therefore cancel out of any saving.
const RetailEnergyRate = 16.0

// PVOutput returns a plant's output for an hour as a fraction of
// nameplate capacity, from clear-sky solar geometry at ~51.5 N in May.
// Deterministic, so the demo is reproducible.
func PVOutput(hour int) float64 {
	const sunrise, sunset = 5.0, 21.0
	h := float64(hour) + 0.5
	if h < sunrise || h > sunset {
		return 0
	}
	return 0.92 * math.Sin(math.Pi*(h-sunrise)/(sunset-sunrise))
}

// LoadShape returns a residential block's demand for an hour as a
// fraction of its daily peak: a morning shoulder and a strong evening
// peak, which is precisely why it overlaps solar so poorly.
func LoadShape(hour int) float64 {
	shape := []float64{
		.40, .37, .33, .33, .37, .47, .63, .77,
		.73, .67, .63, .67, .70, .63, .60, .63,
		.73, .87, 1.00, 1.00, .90, .77, .63, .50,
	}
	return shape[hour%24]
}

// Band is the price range a slot can clear in. Both edges are public and
// externally checkable, which is what makes the price guarantee a
// property of the mechanism rather than a promise.
type Band struct {
	Hour       int
	SpotCt     float64 // wholesale reference s(t)
	FloorCt    float64 // seller's opportunity cost, floored at 0
	CapCt      float64 // operator's published pass-through ceiling
	PVFraction float64
}

// BandAt computes the clearing band for an hour.
//
// The floor is max(0, s(t)): a plant curtails rather than pay to inject,
// so its opportunity cost never goes below zero however negative the
// market goes. The cap is the flat-tariff buyer's avoided energy cost.
// The band is therefore *widest* exactly when wholesale prices collapse:
// the surplus comes from the gap between what generation is worth on the
// market and what the buyer would otherwise pay.
func BandAt(hour int) Band {
	spot := DayPrices[hour%24]
	floor := math.Max(0, spot)
	cap := RetailEnergyRate
	if floor > cap {
		floor = cap
	}
	return Band{
		Hour:       hour % 24,
		SpotCt:     spot,
		FloorCt:    floor,
		CapCt:      cap,
		PVFraction: PVOutput(hour % 24),
	}
}
