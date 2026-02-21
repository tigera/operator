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
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// HOOK SYSTEM DOCUMENTATION
//
// This package implements an extensible hook system that allows external code to extend
// the release build and publish workflows without modifying core logic.
//
// HOOK REGISTRATION:
//
// Hooks are registered via init() functions in separate files, Example:
//
//   // myhooks.go
//   func init() {
//       buildPreHook = myBuildPreHook
//       setupHashreleasePreHook = mySetupHashreleasePreHook
//       publishPreHook = myPublishPreHook
//       postPublishHook = myPostPublishHook
//   }
//
// HOOK EXECUTION AND ERROR HANDLING:
//
// - Hooks are executed with a derived context that includes the main operation's context
// - If a hook times out, the error message clearly indicates which hook timed out
// - If a hook returns an error, it is wrapped with context about which hook failed
// - If a hook panics, the panic is NOT caught - letting it propagate to the caller
// - Hook errors are fatal and stop the entire operation
// - Timeout values can be configured via the --hook-timeout flag,
//   and should be set based on expected hook execution time and overall operation time budget
//
// TIMEOUT CONFIGURATION:
//
// Timeout is configured via the --hook-timeout flag (default: 5 minutes).

// DefaultHookTimeout is the default timeout for all hooks (5 minutes).
const DefaultHookTimeout = 5 * time.Minute

// cliHookFunc is the signature for general purpose hooks that run during command execution.
type cliHookFunc func(ctx context.Context, c *cli.Command) error

// cliBeforeHookFunc is the signature for hooks that run in the cli.BeforeFunc phase and can modify the context for subsequent actions.
type cliBeforeHookFunc func(ctx context.Context, c *cli.Command) (context.Context, error)

// cliHookWithRepoDirFunc is the signature for hooks that require access to the repository root directory (e.g., hashrelease setup).
type cliHookWithRepoDirFunc func(ctx context.Context, c *cli.Command, repoRootDir string) (context.Context, error)

// imageReleaseHookFunc is the signature for hooks that run in publish action after images are published (or skipped).
// It receives information about whether the release was newly published, allowing it to perform actions accordingly.
type imageReleaseHookFunc func(ctx context.Context, c *cli.Command, published bool) (context.Context, error)

type cliHook struct {
	Desc string
	Hook cliHookFunc
}

type multiHook struct {
	mu    sync.Mutex
	hooks []cliHook
}

func (h *multiHook) Add(desc string, hook cliHookFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hooks = append(h.hooks, cliHook{
		Desc: desc,
		Hook: hook,
	})
}

func (h *multiHook) Hooks() []cliHook {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hooks
}

func (h *multiHook) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hooks = nil
}

type withTimeoutResult[T any] struct {
	value T
	err   error
}

// withTimeout is a generic helper that executes a function with timeout and error handling.
// It distinguishes between timeout and other errors and provides clear error messages.
// If the timeout is <= 0, it will use the DefaultHookTimeout.
//
// The hook function receives a cancellable context derived from the parent. On timeout or
// parent cancellation, this context is cancelled to signal the hook to stop. On success,
// the context is intentionally not cancelled so that any context the hook returns (which
// may be derived from it) remains valid for the caller.
//
// Hook functions should respect context cancellation (e.g., use context-aware I/O)
// to ensure the goroutine exits promptly when a timeout or cancellation occurs.
func withTimeout[T any](ctx context.Context, timeout time.Duration, hookName string, fn func(context.Context) (T, error)) (T, error) {
	zero := new(T) // zero value for type T
	if fn == nil {
		return *zero, nil
	}
	if timeout <= 0 {
		timeout = DefaultHookTimeout
	}
	logrus.WithFields(logrus.Fields{
		"hook":    hookName,
		"timeout": timeout,
	}).Debug("Running hook")

	hookCtx, hookCancel := context.WithCancel(ctx)
	// Cancel the hook context on any non-success path to signal the hook goroutine to stop.
	// On success, hookCancel is NOT called because the returned value may be a context
	// derived from hookCtx, and cancelling it would invalidate the caller's context.
	succeeded := false
	defer func() {
		if !succeeded {
			hookCancel()
		}
	}()

	timer := time.NewTimer(timeout)
	done := make(chan withTimeoutResult[T], 1)
	go func() {
		value, err := fn(hookCtx)
		done <- withTimeoutResult[T]{value, err}
	}()

	select {
	case r := <-done:
		timer.Stop()
		if r.err != nil {
			return r.value, fmt.Errorf("%s failed: %w", hookName, r.err)
		}
		succeeded = true
		return r.value, nil
	case <-timer.C:
		return *zero, fmt.Errorf("%s timed out after %v", hookName, timeout)
	case <-ctx.Done():
		timer.Stop()
		return *zero, fmt.Errorf("%s: parent context cancelled: %w", hookName, ctx.Err())
	}
}

// RunBuildBeforeHook executes the buildBeforeHook with timeout and error handling.
func RunBuildBeforeHook(ctx context.Context, c *cli.Command, timeout time.Duration) (context.Context, error) {
	if buildBeforeHook == nil {
		return ctx, nil
	}
	return withTimeout(ctx, timeout, "buildBeforeHook", func(hookCtx context.Context) (context.Context, error) {
		return buildBeforeHook(hookCtx, c)
	})
}

// RunBuildAfterHook executes the buildAfterHook with timeout and error handling.
func RunBuildAfterHook(ctx context.Context, c *cli.Command, timeout time.Duration) error {
	hooks := buildAfterHooks.Hooks()
	if len(hooks) == 0 {
		return nil
	}
	_, err := withTimeout(ctx, timeout, "buildAfterHook", func(hookCtx context.Context) (context.Context, error) {
		// Run all registered build after hooks in LIFO order.
		// All hooks run even if earlier ones fail, to ensure cleanup always happens.
		var errs []error
		for i := len(hooks) - 1; i >= 0; i-- {
			h := hooks[i]
			logrus.WithField("hook", h.Desc).Debug("Running build after hook")
			if err := h.Hook(hookCtx, c); err != nil {
				logrus.WithError(err).WithField("hook", h.Desc).Error("Build after hook failed")
				errs = append(errs, fmt.Errorf("build after hook %q failed: %w", h.Desc, err))
			}
		}
		return hookCtx, errors.Join(errs...)
	})
	return err
}

// RunSetupHashreleasePreHook executes the setupHashreleasePreHook with timeout and error handling.
func RunSetupHashreleasePreHook(ctx context.Context, c *cli.Command, repoRootDir string, timeout time.Duration) (context.Context, error) {
	if setupHashreleasePreHook == nil {
		return ctx, nil
	}
	logrus.WithField("repoDir", repoRootDir).Debug("Running setupHashreleasePreHook")
	return withTimeout(ctx, timeout, "setupHashreleasePreHook", func(hookCtx context.Context) (context.Context, error) {
		return setupHashreleasePreHook(hookCtx, c, repoRootDir)
	})
}

// RunPublishBeforeHook executes the publishBeforeHook with timeout and error handling.
// It wraps any errors to clearly indicate which hook failed and why.
func RunPublishBeforeHook(ctx context.Context, c *cli.Command, timeout time.Duration) (context.Context, error) {
	if publishBeforeHook == nil {
		return ctx, nil
	}
	return withTimeout(ctx, timeout, "publishBeforeHook", func(hookCtx context.Context) (context.Context, error) {
		return publishBeforeHook(hookCtx, c)
	})
}

// RunPublishImagePostHook executes the postPublishHook with timeout and error handling.
func RunPublishImagePostHook(ctx context.Context, c *cli.Command, published bool, timeout time.Duration) (context.Context, error) {
	if publishImagePostHook == nil {
		return ctx, nil
	}
	logrus.WithField("newlyPublished", published).Debug("Running postPublishHook")
	return withTimeout(ctx, timeout, "postPublishHook", func(hookCtx context.Context) (context.Context, error) {
		return publishImagePostHook(hookCtx, c, published)
	})
}
