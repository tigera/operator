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

package operator

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// InstallationPrep is the input to an InstallationExtension's Prepare. It holds
// the generically-gathered reconcile state the extension needs to do its
// side-effecting work (create certs, assemble the trusted bundle).
type InstallationPrep struct {
	Ctx                context.Context
	Client             client.Client
	Installation       *operatorv1.InstallationSpec
	FelixConfiguration *v3.FelixConfiguration
	CertificateManager certificatemanager.CertificateManager
	TrustedBundle      certificatemanagement.TrustedBundle
	ClusterDomain      string
}

// InstallationExtension is the enterprise hook for the installation controller.
// Prepare runs controller-side before rendering. It performs work modifiers
// can't (cluster side effects, fetching/creating certificates) and may abort
// the reconcile by returning an error. It returns the Context handed to the
// render patches; on the Calico variant it should return an empty Context and
// nil error.
type InstallationExtension interface {
	Prepare(p InstallationPrep) (Context, error)
}

var installationExtension InstallationExtension

// RegisterInstallationExtension registers the installation controller extension.
func RegisterInstallationExtension(e InstallationExtension) { installationExtension = e }

// GetInstallationExtension returns the registered extension, or nil.
func GetInstallationExtension() InstallationExtension { return installationExtension }

// ResetExtensionsForTest clears registered extensions. Test-only.
func ResetExtensionsForTest() { installationExtension = nil }
