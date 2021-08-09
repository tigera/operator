// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package render

import (
	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/k8sapi"
)

var (
	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
	TyphaTLSSecretName   = "typha-certs"
	NodeTLSSecretName    = "node-certs"
	TLSSecretCertName    = "cert.crt"
	TLSSecretKeyName     = "key.key"
	CommonName           = "common-name"
	URISAN               = "uri-san"
	TyphaCommonName      = "typha-server"
	FelixCommonName      = "typha-client"
)

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

func Calico(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	logStorageExists bool,
	managementCluster *operator.ManagementCluster,
	managementClusterConnection *operator.ManagementClusterConnection,
	authentication *operator.Authentication,
	pullSecrets []*corev1.Secret,
	managerInternalTLSSecret *corev1.Secret,
	elasticsearchSecret *corev1.Secret,
	kibanaSecret *corev1.Secret,
	bt map[string]string,
	up bool,
	clusterDomain string,
	enableESOIDCWorkaround bool,
	kubeControllersGatewaySecret *corev1.Secret,
	kubeControllersMetricsPort int,
	bgpLayout *corev1.ConfigMap,
) (Renderer, error) {
	var tss []*corev1.Secret

	// If internal manager cert secret exists add it to the renderer.
	if managerInternalTLSSecret != nil {
		tss = append(tss, managerInternalTLSSecret)
	}

	return calicoRenderer{
		k8sServiceEp:                 k8sServiceEp,
		installation:                 cr,
		logStorageExists:             logStorageExists,
		managementCluster:            managementCluster,
		managementClusterConnection:  managementClusterConnection,
		pullSecrets:                  pullSecrets,
		elasticsearchSecret:          elasticsearchSecret,
		kibanaSecret:                 kibanaSecret,
		managerInternalTLSecret:      managerInternalTLSSecret,
		authentication:               authentication,
		enableESOIDCWorkaround:       enableESOIDCWorkaround,
		clusterDomain:                clusterDomain,
		kubeControllersGatewaySecret: kubeControllersGatewaySecret,
		kubeControllersMetricsPort:   kubeControllersMetricsPort,
	}, nil
}

type calicoRenderer struct {
	k8sServiceEp                 k8sapi.ServiceEndpoint
	installation                 *operator.InstallationSpec
	logStorageExists             bool
	managementCluster            *operator.ManagementCluster
	managementClusterConnection  *operator.ManagementClusterConnection
	pullSecrets                  []*corev1.Secret
	managerInternalTLSecret      *corev1.Secret
	elasticsearchSecret          *corev1.Secret
	kibanaSecret                 *corev1.Secret
	authentication               *operator.Authentication
	clusterDomain                string
	enableESOIDCWorkaround       bool
	kubeControllersGatewaySecret *corev1.Secret
	kubeControllersMetricsPort   int
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	// TODO: PriorityClass can just be part of the node renderer.
	components = appendNotNil(components, PriorityClassDefinitions())

	// TODO: Move this out of the calicoRenderer.
	components = appendNotNil(components, Namespaces(r.installation, r.pullSecrets))

	// TODO: Move this out of the calicoRenderer.
	components = appendNotNil(components, KubeControllers(r.k8sServiceEp, r.installation, r.logStorageExists, r.managementCluster,
		r.managementClusterConnection, r.managerInternalTLSecret, r.elasticsearchSecret, r.kibanaSecret, r.authentication,
		r.enableESOIDCWorkaround, r.clusterDomain, r.kubeControllersGatewaySecret, r.kubeControllersMetricsPort))

	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}

func SetTestLogger(l logr.Logger) {
	log = l
}
