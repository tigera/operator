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

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/common"
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
)

type Component interface {
	// Objects returns the lists of objects in this component that should be created and/or deleted during
	// rendering.
	Objects() (objsToCreate, objsToDelete []runtime.Object)

	// Ready returns true if the component is ready to be created.
	Ready() bool
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
	cr *operator.Installation,
	pullSecrets []*corev1.Secret,
	typhaNodeTLS *TyphaNodeTLS,
	managerTLSSecret *corev1.Secret,
	bt map[string]string,
	p operator.Provider,
	nc NetworkConfig,
	up bool,
) (Renderer, error) {

	tcms := []*corev1.ConfigMap{}
	tss := []*corev1.Secret{}

	if typhaNodeTLS == nil {
		typhaNodeTLS = &TyphaNodeTLS{}
	}

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
	tcm := typhaNodeTLS.CAConfigMap.DeepCopy()
	tcm.ObjectMeta = metav1.ObjectMeta{Name: typhaNodeTLS.CAConfigMap.Name, Namespace: common.CalicoNamespace}
	tcms = append(tcms, tcm)

	ts := typhaNodeTLS.TyphaSecret.DeepCopy()
	ts.ObjectMeta = metav1.ObjectMeta{Name: ts.Name, Namespace: common.CalicoNamespace}
	ns := typhaNodeTLS.NodeSecret.DeepCopy()
	ns.ObjectMeta = metav1.ObjectMeta{Name: ns.Name, Namespace: common.CalicoNamespace}
	tss = append(tss, ts, ns)

	if managerTLSSecret == nil && cr.Spec.Variant == operator.TigeraSecureEnterprise && cr.Spec.ClusterManagementType == operator.ClusterManagementTypeManagement {
		// Generate CA and TLS certificate for tigera-manager
		log.Info("Creating secret for manager")
		var err error
		managerTLSSecret, err = CreateOperatorTLSSecret(nil,
			ManagerTLSSecretName,
			ManagerSecretKeyName,
			ManagerSecretCertName,
			825*24*time.Hour, // 825days*24hours: Create cert with a max expiration that macOS 10.15 will accept
			nil,
			ManagerServiceIP,
			ManagerServiceDNS,
		)
		if err != nil {
			return nil, fmt.Errorf("generating certificates for manager was not finalized due to %v", err)
		}
		tss = append(tss, managerTLSSecret)
	}

	return calicoRenderer{
		installation:    cr,
		pullSecrets:     pullSecrets,
		typhaNodeTLS:    typhaNodeTLS,
		tlsConfigMaps:   tcms,
		tlsSecrets:      tss,
		managerTLSecret: managerTLSSecret,
		birdTemplates:   bt,
		provider:        p,
		networkConfig:   nc,
		upgrade:         up,
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
		"typha-client")
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.NodeSecret.Data[CommonName] = []byte("typha-client")

	// Create TLS Secret for Felix using ca from above
	tntls.TyphaSecret, err = CreateOperatorTLSSecret(ca,
		TyphaTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		DefaultCertificateDuration,
		[]crypto.CertificateExtensionFunc{setServerAuth},
		"typha-server")
	if err != nil {
		return nil, err
	}
	// Set the CommonName used to create cert
	tntls.TyphaSecret.Data[CommonName] = []byte("typha-server")

	return &tntls, nil
}

type calicoRenderer struct {
	installation    *operator.Installation
	pullSecrets     []*corev1.Secret
	typhaNodeTLS    *TyphaNodeTLS
	tlsConfigMaps   []*corev1.ConfigMap
	tlsSecrets      []*corev1.Secret
	managerTLSecret *corev1.Secret
	birdTemplates   map[string]string
	provider        operator.Provider
	networkConfig   NetworkConfig
	upgrade         bool
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.provider == operator.ProviderOpenShift, r.pullSecrets))
	components = appendNotNil(components, ConfigMaps(r.tlsConfigMaps))
	components = appendNotNil(components, Secrets(r.tlsSecrets))
	components = appendNotNil(components, Typha(r.installation, r.provider, r.typhaNodeTLS, r.upgrade))
	components = appendNotNil(components, Node(r.installation, r.provider, r.networkConfig, r.birdTemplates, r.typhaNodeTLS, r.upgrade))
	components = appendNotNil(components, KubeControllers(r.installation, r.managerTLSecret))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
