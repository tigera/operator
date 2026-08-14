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

package extensions

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// StartupExtension is the variant's hook into operator startup, before any
// controller runs.
type StartupExtension interface {
	// VerifyConfiguration rejects a configuration the variant refuses to run with.
	VerifyConfiguration(ctx context.Context, cs kubernetes.Interface) error
}

// noopStartup accepts whatever configuration the core operator was given.
type noopStartup struct{}

func (noopStartup) VerifyConfiguration(context.Context, kubernetes.Interface) error {
	return nil
}
