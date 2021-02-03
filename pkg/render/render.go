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
	"bytes"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/tigera/operator/pkg/tls"

	rcommon "github.com/tigera/operator/pkg/render/common"

	"github.com/tigera/operator/pkg/render/component"

	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
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
	Render() []component.Component
}

type TyphaNodeTLS struct {
	CAConfigMap *corev1.ConfigMap
	TyphaSecret *corev1.Secret
	NodeSecret  *corev1.Secret
}

func Calico(
	k8sServiceEp k8sapi.ServiceEndpoint,
	cr *operator.InstallationSpec,
	logStorageExists bool,
	managementCluster *operator.ManagementCluster,
	managementClusterConnection *operator.ManagementClusterConnection,
	authentication *operator.Authentication,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *TyphaNodeTLS,
	managerInternalTLSSecret *corev1.Secret,
	elasticsearchSecret *corev1.Secret,
	kibanaSecret *corev1.Secret,
	bt map[string]string,
	p operator.Provider,
	aci *operator.AmazonCloudIntegration,
	up bool,
	nodeAppArmorProfile string,
	clusterDomain string,
	esLicenseType ElasticsearchLicenseType,
) (Renderer, error) {
	var tcms []*corev1.ConfigMap
	var tss []*corev1.Secret

	if cr.CertificateManagement != nil {
		typhaNodeTLS = &TyphaNodeTLS{
			CAConfigMap: &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      TyphaCAConfigMapName,
					Namespace: rcommon.OperatorNamespace(),
				},
				Data: map[string]string{
					TyphaCABundleName: string(cr.CertificateManagement.CACert),
				},
			},
		}
	} else {
		// Check the CA configMap and Secrets to ensure they are a valid combination and
		// if the TLS info needs to be created.
		// We should have them all or none.
		if typhaNodeTLS.CAConfigMap == nil {
			if typhaNodeTLS.TyphaSecret != nil || typhaNodeTLS.NodeSecret != nil {
				return nil, fmt.Errorf("Typha-Felix CA config map did not exist and neither should the Secrets (%v)", typhaNodeTLS)
			}
			var err error
			typhaNodeTLS, err = createTLS()
			if err != nil {
				return nil, fmt.Errorf("Failed to create Typha TLS: %s", err)
			}
			tcms = append(tcms, typhaNodeTLS.CAConfigMap)
			tss = append(tss, typhaNodeTLS.TyphaSecret, typhaNodeTLS.NodeSecret)
		} else {
			// CA ConfigMap exists
			if typhaNodeTLS.TyphaSecret == nil || typhaNodeTLS.NodeSecret == nil {
				return nil, fmt.Errorf("Typha-Felix CA config map exists and so should the Secrets.")
			}
		}
		// Create copy to go into Calico Namespace
		tss = append(tss, rcommon.CopySecrets(common.CalicoNamespace, typhaNodeTLS.TyphaSecret, typhaNodeTLS.NodeSecret)...)
	}
	// Create copy to go into Calico Namespace
	tcms = append(tcms, rcommon.CopyConfigMaps(common.CalicoNamespace, typhaNodeTLS.CAConfigMap)...)

	// If internal manager cert secret exists add it to the renderer.
	if managerInternalTLSSecret != nil {
		tss = append(tss, managerInternalTLSSecret)
	}

	return calicoRenderer{
		k8sServiceEp:                k8sServiceEp,
		installation:                cr,
		logStorageExists:            logStorageExists,
		managementCluster:           managementCluster,
		managementClusterConnection: managementClusterConnection,
		pullSecrets:                 pullSecrets,
		typhaNodeTLS:                typhaNodeTLS,
		tlsConfigMaps:               tcms,
		tlsSecrets:                  tss,
		elasticsearchSecret:         elasticsearchSecret,
		kibanaSecret:                kibanaSecret,
		managerInternalTLSecret:     managerInternalTLSSecret,
		birdTemplates:               bt,
		provider:                    p,
		amazonCloudInt:              aci,
		upgrade:                     up,
		authentication:              authentication,
		nodeAppArmorProfile:         nodeAppArmorProfile,
		esLicenseType:               esLicenseType,
		clusterDomain:               clusterDomain,
	}, nil
}

func createTLS() (*TyphaNodeTLS, error) {
	// Make CA
	ca, err := tls.MakeCA(fmt.Sprintf("%s@%d", rcommon.TigeraOperatorCAIssuerPrefix, time.Now().Unix()))
	if err != nil {
		return nil, err
	}
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := ca.Config.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	tntls := TyphaNodeTLS{}
	// Take CA cert and create ConfigMap
	data := make(map[string]string)
	data[TyphaCABundleName] = crtContent.String()
	tntls.CAConfigMap = &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaCAConfigMapName,
			Namespace: rcommon.OperatorNamespace(),
		},
		Data: data,
	}

	// Create TLS Secret for Felix using ca from above
	tntls.NodeSecret, err = rcommon.CreateOperatorTLSSecret(ca,
		NodeTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		rcommon.DefaultCertificateDuration,
		[]crypto.CertificateExtensionFunc{tls.SetClientAuth},
		FelixCommonName)
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.NodeSecret.Data[CommonName] = []byte(FelixCommonName)

	// Create TLS Secret for Felix using ca from above
	tntls.TyphaSecret, err = rcommon.CreateOperatorTLSSecret(ca,
		TyphaTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		rcommon.DefaultCertificateDuration,
		[]crypto.CertificateExtensionFunc{tls.SetServerAuth},
		TyphaCommonName)
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.TyphaSecret.Data[CommonName] = []byte(TyphaCommonName)

	return &tntls, nil
}

type calicoRenderer struct {
	k8sServiceEp                k8sapi.ServiceEndpoint
	installation                *operator.InstallationSpec
	logStorageExists            bool
	managementCluster           *operator.ManagementCluster
	managementClusterConnection *operator.ManagementClusterConnection
	pullSecrets                 []*corev1.Secret
	typhaNodeTLS                *TyphaNodeTLS
	tlsConfigMaps               []*corev1.ConfigMap
	tlsSecrets                  []*corev1.Secret
	managerInternalTLSecret     *corev1.Secret
	elasticsearchSecret         *corev1.Secret
	kibanaSecret                *corev1.Secret
	birdTemplates               map[string]string
	provider                    operator.Provider
	amazonCloudInt              *operator.AmazonCloudIntegration
	upgrade                     bool
	authentication              *operator.Authentication
	nodeAppArmorProfile         string
	clusterDomain               string
	esLicenseType               ElasticsearchLicenseType
}

func (r calicoRenderer) Render() []component.Component {
	var components []component.Component
	components = appendNotNil(components, PriorityClassDefinitions())
	components = appendNotNil(components, Namespaces(r.installation, r.pullSecrets))
	components = appendNotNil(components, ConfigMaps(r.tlsConfigMaps))
	components = appendNotNil(components, Secrets(r.tlsSecrets))
	components = appendNotNil(components, Typha(r.k8sServiceEp, r.installation, r.typhaNodeTLS, r.amazonCloudInt, r.upgrade, r.clusterDomain))
	components = appendNotNil(components, Node(r.k8sServiceEp, r.installation, r.birdTemplates, r.typhaNodeTLS, r.amazonCloudInt, r.upgrade, r.nodeAppArmorProfile, r.clusterDomain))
	components = appendNotNil(components, KubeControllers(r.k8sServiceEp, r.installation, r.logStorageExists, r.managementCluster, r.managementClusterConnection, r.managerInternalTLSecret, r.elasticsearchSecret, r.kibanaSecret, r.authentication, r.esLicenseType))
	return components
}

func appendNotNil(components []component.Component, c component.Component) []component.Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}

func SetTestLogger(l logr.Logger) {
	log = l
}
