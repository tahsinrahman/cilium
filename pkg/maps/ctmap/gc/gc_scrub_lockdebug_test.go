// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build lockdebug

package gc

import "github.com/sasha-s/go-deadlock"

func init() {
	// The deadlock detector pools its timers. One created in a synctest bubble
	// panics when another test, outside the bubble, gets it from the pool.
	deadlock.Opts.TimerPool = deadlock.TimerPoolDisabled
}
