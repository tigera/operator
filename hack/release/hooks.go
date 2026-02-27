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
	"slices"
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
// HOOK NAME AND SIGNATURE CONVENTIONS:
// - Workflow hooks are multiHook variables that can have multiple registered hooks.
//   See "HOOKS EXECUTION AND ERROR HANDLING" below for execution order and error handling details.
// - Hooks are categorized by the phase of the workflow they run in and follow the naming convention: <phase><Before|After>Hook. For example:
//   - buildBeforeHook: runs before the build phase
//   - publishImagesAfterHook: runs after the publish images phase
// - Each hook type has a specific function signature that defines the parameters it receives and if it can modify the context for subsequent actions. For example:
//   - cliHookFunc does not modify the context: func(ctx context.Context, c *cli.Command) error
//   - cliBeforeHookFunc can modify the context: func(ctx context.Context, c *cli.Command) (context.Context, error)
//
// HOOK REGISTRATION:
//
// Hooks are registered by calling the Add method on the appropriate multiHook variable, typically from an init() function. For example:
//
//   // myhooks.go
//   func init() {
//       buildBeforeHook.Add("my custom before hook", myCustomBuildBeforeHook)
//       buildAfterHook.Add("my custom after hook", myCustomBuildAfterHook)
//   }
//
// HOOK EXECUTION AND ERROR HANDLING:
//
// - Hooks are executed with a derived context that includes the main operation's context
// - Hooks that run in the "Before" phase (e.g., buildBeforeHook) run in registration order and stop on the first error (fail-fast).
// - Hooks that run in the "After" phase (e.g., buildAfterHook) run in reverse registration order and collect all errors, returning them as a single error.
// - If a hook times out, the error message clearly indicates which hook timed out
// - If a hook returns an error, it is wrapped with context about which hook failed
// - If a hook panics, the panic is NOT caught - letting it propagate to the caller
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

type cliHook[T any] struct {
	Desc string
	Hook T
}

type multiHook[T any] struct {
	mu    sync.Mutex
	hooks []cliHook[T]
}

func (h *multiHook[T]) Add(desc string, hook T) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hooks = append(h.hooks, cliHook[T]{
		Desc: desc,
		Hook: hook,
	})
}

func (h *multiHook[T]) Hooks() []cliHook[T] {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.hooks)
}

func (h *multiHook[T]) Reset() {
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

// runHooksFailFast runs all hooks in registration order, stopping on the first error.
func runHooksFailFast[T any](
	ctx context.Context,
	timeout time.Duration,
	hookName string,
	mh *multiHook[T],
	run func(T, context.Context) (context.Context, error),
) (context.Context, error) {
	hooks := mh.Hooks()
	if len(hooks) == 0 {
		return ctx, nil
	}
	return withTimeout(ctx, timeout, hookName, func(hookCtx context.Context) (context.Context, error) {
		for _, h := range hooks {
			var err error
			hookCtx, err = run(h.Hook, hookCtx)
			if err != nil {
				return hookCtx, fmt.Errorf("%s %q failed: %w", hookName, h.Desc, err)
			}
		}
		return hookCtx, nil
	})
}

// runHooksCollectErrors runs all hooks in reverse (LIFO) order, collecting all errors.
func runHooksCollectErrors[T any](
	ctx context.Context,
	timeout time.Duration,
	hookName string,
	mh *multiHook[T],
	run func(T, context.Context) (context.Context, error),
) (context.Context, error) {
	hooks := mh.Hooks()
	if len(hooks) == 0 {
		return ctx, nil
	}
	return withTimeout(ctx, timeout, hookName, func(hookCtx context.Context) (context.Context, error) {
		var errs []error
		for i := len(hooks) - 1; i >= 0; i-- {
			var err error
			hookCtx, err = run(hooks[i].Hook, hookCtx)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s %q failed: %w", hookName, hooks[i].Desc, err))
			}
		}
		return hookCtx, errors.Join(errs...)
	})
}

// RunBuildBeforeHook executes the buildBeforeHook with timeout and error handling.
func RunBuildBeforeHook(ctx context.Context, c *cli.Command, timeout time.Duration) (context.Context, error) {
	return runHooksFailFast(ctx, timeout, "buildBeforeHook", &buildBeforeHook,
		func(h cliBeforeHookFunc, ctx context.Context) (context.Context, error) {
			return h(ctx, c)
		})
}

// RunBuildAfterHook executes the buildAfterHook with timeout and error handling.
func RunBuildAfterHook(ctx context.Context, c *cli.Command, timeout time.Duration) error {
	_, err := runHooksCollectErrors(ctx, timeout, "buildAfterHook", &buildAfterHooks,
		func(h cliHookFunc, ctx context.Context) (context.Context, error) {
			return ctx, h(ctx, c)
		})
	return err
}

// RunSetupHashreleaseBeforeHook executes the setupHashreleaseBeforeHook with timeout and error handling.
func RunSetupHashreleaseBeforeHook(ctx context.Context, c *cli.Command, repoRootDir string, timeout time.Duration) (context.Context, error) {
	return runHooksFailFast(ctx, timeout, "setupHashreleaseBeforeHook", &setupHashreleaseBeforeHook,
		func(h cliHookWithRepoDirFunc, ctx context.Context) (context.Context, error) {
			return h(ctx, c, repoRootDir)
		})
}

// RunPublishBeforeHook executes the publishBeforeHook with timeout and error handling.
func RunPublishBeforeHook(ctx context.Context, c *cli.Command, timeout time.Duration) (context.Context, error) {
	return runHooksFailFast(ctx, timeout, "publishBeforeHook", &publishBeforeHook,
		func(h cliBeforeHookFunc, ctx context.Context) (context.Context, error) {
			return h(ctx, c)
		})
}

// RunPublishImageAfterHook executes the publishImageAfterHook with timeout and error handling.
func RunPublishImageAfterHook(ctx context.Context, c *cli.Command, published bool, timeout time.Duration) (context.Context, error) {
	return runHooksCollectErrors(ctx, timeout, "publishImageAfterHook", &publishImageAfterHook,
		func(h imageReleaseHookFunc, ctx context.Context) (context.Context, error) {
			return h(ctx, c, published)
		})
}
