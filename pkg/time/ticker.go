// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package time

import (
	"time"
)

type Ticker interface {
	Stop()
	Reset(clean time.Duration)
	Chan() <-chan time.Time
}

func NewTicker(duration time.Duration) Ticker {
	return &ticker{
		Ticker: time.NewTicker(duration),
	}
}

type ticker struct {
	*time.Ticker
}

func (t *ticker) Chan() <-chan time.Time {
	return t.C
}
