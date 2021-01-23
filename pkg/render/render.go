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

	"github.com/openshift/library-go/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
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

type Component interface {
	// ResolveImages should call components.GetReference for all images that the Component
	// needs, passing 'is' to the GetReference call and if there are any errors those
	// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
	// ResolveImages must be called before Objects is called for the component.
	ResolveImages(is *operator.ImageSet) error

	// Objects returns the lists of objects in this component that should be created and/or deleted during
	// rendering.
	Objects() (objsToCreate, objsToDelete []runtime.Object)

	// Ready returns true if the component is ready to be created.
	Ready() bool

	// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
	// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on runtime.Objects
	// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
	SupportedOSType() OSType
}

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
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
					Namespace: OperatorNamespace(),
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
		tss = append(tss, CopySecrets(common.CalicoNamespace, typhaNodeTLS.TyphaSecret, typhaNodeTLS.NodeSecret)...)
	}
	// Create copy to go into Calico Namespace
	tcms = append(tcms, CopyConfigMaps(common.CalicoNamespace, typhaNodeTLS.CAConfigMap)...)

	if managerInternalTLSSecret == nil && cr.Variant == operator.TigeraSecureEnterprise && managementCluster != nil {
		// Generate CA and TLS certificate for tigera-manager for internal traffic within the K8s cluster
		// The certificate will be issued for the FQDN manager service names and
		// localhost.
		log.Info("Creating secret for internal manager credentials")
		var err error
		svcDNSNames := dns.GetServiceDNSNames(ManagerServiceName, ManagerNamespace, clusterDomain)
		svcDNSNames = append(svcDNSNames, ManagerServiceIP)

		managerInternalTLSSecret, err = CreateOperatorTLSSecret(nil,
			ManagerInternalTLSSecretName,
			ManagerInternalSecretKeyName,
			ManagerInternalSecretCertName,
			825*24*time.Hour, // 825days*24hours: Create cert with a max expiration that macOS 10.15 will accept
			nil,
			svcDNSNames...,
		)
		if err != nil {
			return nil, fmt.Errorf("generating certificates for manager was not finalized due to %v", err)
		}
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
	ca, err := makeCA()
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
			Namespace: OperatorNamespace(),
		},
		Data: data,
	}

	// Create TLS Secret for Felix using ca from above
	tntls.NodeSecret, err = CreateOperatorTLSSecret(ca,
		NodeTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		DefaultCertificateDuration,
		[]crypto.CertificateExtensionFunc{setClientAuth},
		FelixCommonName)
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.NodeSecret.Data[CommonName] = []byte(FelixCommonName)

	// Create TLS Secret for Felix using ca from above
	tntls.TyphaSecret, err = CreateOperatorTLSSecret(ca,
		TyphaTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		DefaultCertificateDuration,
		[]crypto.CertificateExtensionFunc{setServerAuth},
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
	birdTemplates               map[string]string
	provider                    operator.Provider
	amazonCloudInt              *operator.AmazonCloudIntegration
	upgrade                     bool
	authentication              *operator.Authentication
	nodeAppArmorProfile         string
	clusterDomain               string
	esLicenseType               ElasticsearchLicenseType
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, PriorityClassDefinitions())
	components = appendNotNil(components, Namespaces(r.installation, r.pullSecrets))
	components = appendNotNil(components, ConfigMaps(r.tlsConfigMaps))
	components = appendNotNil(components, Secrets(r.tlsSecrets))
	components = appendNotNil(components, Typha(r.k8sServiceEp, r.installation, r.typhaNodeTLS, r.amazonCloudInt, r.upgrade, r.clusterDomain))
	components = appendNotNil(components, Node(r.k8sServiceEp, r.installation, r.birdTemplates, r.typhaNodeTLS, r.amazonCloudInt, r.upgrade, r.nodeAppArmorProfile, r.clusterDomain))
	components = appendNotNil(components, KubeControllers(r.k8sServiceEp, r.installation, r.logStorageExists, r.managementCluster, r.managementClusterConnection, r.managerInternalTLSecret, r.authentication, r.esLicenseType))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
