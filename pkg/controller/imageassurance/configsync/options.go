// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package configsync

import "time"

type Option func(*syncer)

func WithBastClientCreator(creator BastClientCreator) Option {
	return func(s *syncer) {
		s.bastClientCreator = creator
	}
}

func WithTickerCreator(creator TickerCreator) Option {
	return func(s *syncer) {
		s.tickerCreator = creator
	}
}

func WithReSyncDuration(reSyncDuration time.Duration) Option {
	return func(s *syncer) {
		s.reSyncDuration = reSyncDuration
	}
}
