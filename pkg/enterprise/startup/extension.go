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

package startup

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage"
)

// Extension is the Calico Enterprise startup checks.
type Extension struct {
	opts eoptions.Options
}

var _ extensions.StartupExtension = &Extension{}

// New returns the startup extension.
func New(o eoptions.Options) *Extension {
	return &Extension{opts: o}
}

// VerifyConfiguration refuses to run when the Elasticsearch certificates on disk
// contradict the internal/external mode the operator was configured for.
func (e *Extension) VerifyConfiguration(ctx context.Context, cs kubernetes.Interface) error {
	if e.opts.ESMigration {
		// The final phase of an ES migration has both internal and external ES, so
		// the checks below do not apply.
		return nil
	}

	if e.opts.ExternalElastic {
		if _, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, render.TigeraElasticsearchInternalCertSecret, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently internal: %w", err)
		}
		return fmt.Errorf("refusing to run: configured as external ES but secret/%s found which suggests internal ES", render.TigeraElasticsearchInternalCertSecret)
	}

	if _, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, logstorage.ExternalCertsSecret, metav1.GetOptions{}); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("unexpected error encountered when confirming elastic is not currently external: %w", err)
	}
	return fmt.Errorf("refusing to run: configured as internal-es but secret/%s found which suggests external ES", logstorage.ExternalCertsSecret)
}
