// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package ccs

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const (
	Namespace = "tigera-compliance"
)

func CCS(cfg *Config) render.Component {
	return &component{
		cfg: cfg,
	}
}

type component struct {
	cfg             *Config
	apiImage        string
	controllerImage string

	hostScannerConfigMap       *corev1.ConfigMap
	hostScannerInputsConfigMap *corev1.ConfigMap
}

// Config contains all the config information needed to render the component.
type Config struct {
	Installation                *operatorv1.InstallationSpec
	PullSecrets                 []*corev1.Secret
	OpenShift                   bool
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	KeyValidatorConfig          authentication.KeyValidatorConfig
	ClusterDomain               string
	HasNoLicense                bool

	// Trusted certificate bundle for all ccs pods.
	TrustedBundle certificatemanagement.TrustedBundleRO
	APIKeyPair    certificatemanagement.KeyPairInterface

	Namespace         string
	BindingNamespaces []string

	// Whether to run the rendered components in multi-tenant, single-tenant, or zero-tenant mode
	Tenant                          *operatorv1.Tenant
	ExternalElastic                 bool
	ComplianceConfigurationSecurity *operatorv1.ComplianceConfigurationSecurity
}

func (c *component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error
	errMsgs := []string{}
	c.apiImage, err = components.GetReference(components.ComponentCCSAPI, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	c.controllerImage, err = components.GetReference(components.ComponentCCSController, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *component) Objects() ([]client.Object, []client.Object) {
	var objs []client.Object

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(c.cfg.Namespace, c.cfg.PullSecrets...)...)...)

	objs = append(objs,
		c.apiServiceAccount(),
		c.apiRole(),
		c.apiRoleBinding(),
		c.apiClusterRole(),
		c.apiClusterRoleBinding(),
		c.apiDeployment(),
		c.apiService(),
		c.apiPublicCertConfigMap(),
		c.apiTLSTerminatedRoute(),
		// TODO: the policy is broad but works.
		c.apiAllowTigeraNetworkPolicy(),
	)

	c.hostScannerConfigMap = c.hostScannerYamlConfigMap()
	c.hostScannerInputsConfigMap = c.hostScannerDefaultConfigInputsConfigMap()

	objs = append(objs,
		c.controllerServiceAccount(),
		c.controllerRole(),
		c.controllerRoleBinding(),
		c.controllerClusterRole(),
		c.controllerClusterRoleBinding(),
		c.hostScannerYamlConfigMap(),
		c.hostScannerDefaultConfigInputsConfigMap(),
		c.controllerDeployment(),
		// TODO: the policy is broad but works.
		c.controllerAllowTigeraNetworkPolicy(),
	)

	return objs, nil
}

func (c *component) Ready() bool {
	return true
}
