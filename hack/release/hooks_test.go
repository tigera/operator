// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urfave/cli/v3"
)

func TestWithTimeout(t *testing.T) {
	t.Parallel()

	t.Run("nil function returns zero value", func(t *testing.T) {
		t.Parallel()
		val, err := withTimeout[string](context.Background(), time.Second, "test-hook", nil)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if val != "" {
			t.Fatalf("expected empty string, got: %q", val)
		}
	})

	t.Run("successful execution", func(t *testing.T) {
		t.Parallel()
		val, err := withTimeout(context.Background(), time.Second, "test-hook", func(ctx context.Context) (string, error) {
			return "result", nil
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if val != "result" {
			t.Fatalf("expected %q, got: %q", "result", val)
		}
	})

	t.Run("function returns error", func(t *testing.T) {
		t.Parallel()
		_, err := withTimeout(context.Background(), time.Second, "test-hook", func(ctx context.Context) (string, error) {
			return "", errors.New("hook error")
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "test-hook failed") {
			t.Fatalf("expected error to contain 'test-hook failed', got: %v", err)
		}
		if !strings.Contains(err.Error(), "hook error") {
			t.Fatalf("expected error to contain 'hook error', got: %v", err)
		}
	})

	t.Run("timeout triggers and cancels hook context", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			_, err := withTimeout(context.Background(), 5*time.Minute, "slow-hook", func(ctx context.Context) (string, error) {
				<-ctx.Done()
				return "", ctx.Err()
			})
			if err == nil {
				t.Fatal("expected timeout error, got nil")
			}
			if !strings.Contains(err.Error(), "slow-hook timed out") {
				t.Fatalf("expected timeout error message, got: %v", err)
			}
		})
	})

	t.Run("parent context cancelled cancels hook context", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(1 * time.Minute)
				cancel()
			}()
			_, err := withTimeout(ctx, 5*time.Minute, "cancel-hook", func(ctx context.Context) (string, error) {
				// Hook respects context cancellation, so it exits when the parent is cancelled.
				<-ctx.Done()
				return "", ctx.Err()
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "parent context cancelled") {
				t.Fatalf("expected parent context cancelled error, got: %v", err)
			}
		})
	})

	t.Run("zero timeout uses default", func(t *testing.T) {
		t.Parallel()
		val, err := withTimeout(context.Background(), 0, "test-hook", func(ctx context.Context) (int, error) {
			return 42, nil
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if val != 42 {
			t.Fatalf("expected 42, got: %d", val)
		}
	})
}

// Run* hook tests must NOT be parallel since it uses package-level hook vars that can be mutated by other tests.
func TestRunBuildAfterHookRunsAll(t *testing.T) {
	defer buildAfterHooks.Reset()

	var ran []string
	buildAfterHooks.Add("hook-1", func(ctx context.Context, c *cli.Command) error {
		ran = append(ran, "hook-1")
		return errors.New("hook-1 error")
	})
	buildAfterHooks.Add("hook-2", func(ctx context.Context, c *cli.Command) error {
		ran = append(ran, "hook-2")
		return nil
	})
	buildAfterHooks.Add("hook-3", func(ctx context.Context, c *cli.Command) error {
		ran = append(ran, "hook-3")
		return errors.New("hook-3 error")
	})

	err := RunBuildAfterHook(context.Background(), nil, 5*time.Second)
	// Should have errors from hook-1 and hook-3
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hook-1 error") {
		t.Fatalf("expected hook-1 error in result, got: %v", err)
	}
	if !strings.Contains(err.Error(), "hook-3 error") {
		t.Fatalf("expected hook-3 error in result, got: %v", err)
	}
	// All three hooks should have run (in LIFO order: hook-3, hook-2, hook-1)
	if len(ran) != 3 {
		t.Fatalf("expected all 3 hooks to run, got %d: %v", len(ran), ran)
	}
	if ran[0] != "hook-3" || ran[1] != "hook-2" || ran[2] != "hook-1" {
		t.Fatalf("expected LIFO order [hook-3, hook-2, hook-1], got %v", ran)
	}
}

// Run* hook tests must NOT be parallel since it uses package-level hook vars that can be mutated by other tests.
func TestRunHookErrorPropagation(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(errMsg string)
		run     func() error
		cleanup func()
	}{
		{
			name: "RunBuildBeforeHook",
			setup: func(errMsg string) {
				buildBeforeHook.Add("test-hook", func(ctx context.Context, c *cli.Command) (context.Context, error) {
					return ctx, errors.New(errMsg)
				})
			},
			run: func() error {
				_, err := RunBuildBeforeHook(context.Background(), nil, time.Second)
				return err
			},
			cleanup: func() { buildBeforeHook.Reset() },
		},
		{
			name: "RunBuildAfterHook",
			setup: func(errMsg string) {
				buildAfterHooks.Add("test-hook", func(ctx context.Context, c *cli.Command) error {
					return errors.New(errMsg)
				},
				)
			},
			run: func() error {
				return RunBuildAfterHook(context.Background(), nil, time.Second)
			},
			cleanup: func() { buildAfterHooks.Reset() },
		},
		{
			name: "RunSetupHashreleasePreHook",
			setup: func(errMsg string) {
				setupHashreleaseBeforeHook.Add("test-hook", func(ctx context.Context, c *cli.Command, dir string) (context.Context, error) {
					return ctx, errors.New(errMsg)
				})
			},
			run: func() error {
				_, err := RunSetupHashreleaseBeforeHook(context.Background(), nil, "/tmp", time.Second)
				return err
			},
			cleanup: func() { setupHashreleaseBeforeHook.Reset() },
		},
		{
			name: "RunPublishBeforeHook",
			setup: func(errMsg string) {
				publishBeforeHook.Add("test-hook", func(ctx context.Context, c *cli.Command) (context.Context, error) {
					return ctx, errors.New(errMsg)
				})
			},
			run: func() error {
				_, err := RunPublishBeforeHook(context.Background(), nil, time.Second)
				return err
			},
			cleanup: func() { publishBeforeHook.Reset() },
		},
		{
			name: "RunPublishImagePostHook",
			setup: func(errMsg string) {
				publishImageAfterHook.Add("test-hook", func(ctx context.Context, c *cli.Command, published bool) (context.Context, error) {
					return ctx, errors.New(errMsg)
				})
			},
			run: func() error {
				_, err := RunPublishImageAfterHook(context.Background(), nil, true, time.Second)
				return err
			},
			cleanup: func() { publishImageAfterHook.Reset() },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.cleanup()
			errMsg := tc.name + " failed"
			tc.setup(errMsg)
			err := tc.run()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), errMsg) {
				t.Fatalf("expected error to contain %q, got: %v", errMsg, err)
			}
		})
	}
}

// Run* hook tests must NOT be parallel since it uses package-level hook vars that can be mutated by other tests.
func TestRunHooksNilNoOp(t *testing.T) {
	ctx := context.Background()

	t.Run("RunBuildBeforeHook", func(t *testing.T) {
		if rCtx, err := RunBuildBeforeHook(ctx, nil, time.Second); err != nil {
			t.Fatalf("RunBuildPreHook with nil hook: %v", err)
		} else if rCtx != ctx {
			t.Fatal("RunBuildPreHook should return the original context when hook is nil")
		}
	})

	t.Run("RunBuildAfterHook", func(t *testing.T) {
		if err := RunBuildAfterHook(ctx, nil, time.Second); err != nil {
			t.Fatalf("RunBuildAfterHook with nil hook: %v", err)
		}
	})

	t.Run("RunSetupHashreleasePreHook", func(t *testing.T) {
		if rCtx, err := RunSetupHashreleaseBeforeHook(ctx, nil, "/tmp", time.Second); err != nil {
			t.Fatalf("RunSetupHashreleasePreHook with nil hook: %v", err)
		} else if rCtx != ctx {
			t.Fatal("RunSetupHashreleasePreHook should return the original context when hook is nil")
		}
	})

	t.Run("RunPublishBeforeHook", func(t *testing.T) {
		if rCtx, err := RunPublishBeforeHook(ctx, nil, time.Second); err != nil {
			t.Fatalf("RunPublishPreHook with nil hook: %v", err)
		} else if rCtx != ctx {
			t.Fatal("RunPublishPreHook should return the original context when hook is nil")
		}
	})

	t.Run("RunPublishImagePostHook", func(t *testing.T) {
		if rCtx, err := RunPublishImageAfterHook(ctx, nil, true, time.Second); err != nil {
			t.Fatalf("RunPostPublishHook with nil hook: %v", err)
		} else if rCtx != ctx {
			t.Fatal("RunPostPublishHook should return the original context when hook is nil")
		}
	})
}
