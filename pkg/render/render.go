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

	"github.com/openshift/library-go/pkg/crypto"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	TyphaCAConfigMapName = "typha-ca"
	TyphaCABundleName    = "caBundle"
	TyphaTLSSecretName   = "typha-certs"
	FelixTLSSecretName   = "felix-certs"
	TLSSecretCertName    = "cert.crt"
	TLSSecretKeyName     = "key.key"
	CommonName           = "common-name"
	URISAN               = "uri-san"
)

type Component interface {
	// Objects returns all objects this component contains.
	Objects() []runtime.Object

	// Ready returns true if the component is ready to be created.
	Ready() bool
}

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

func Calico(
	cr *operator.Installation,
	pullSecrets []*corev1.Secret,
	typhaCAConfigMap *corev1.ConfigMap,
	typhaSecrets []*corev1.Secret,
	bt map[string]string,
	p operator.Provider,
	nc NetworkConfig,
) (Renderer, error) {

	tcms := []*corev1.ConfigMap{}
	tss := []*corev1.Secret{}

	// Check the CA configMap and Secrets to ensure they are a valid combination and
	// if the TLS info needs to be created.
	// We should have them all or none.
	if typhaCAConfigMap == nil {
		if len(typhaSecrets) != 0 {
			return nil, fmt.Errorf("Typha-Felix CA config map did not exist and neither should the Secrets Secrets(%v)", typhaSecrets)
		}
		var err error
		typhaCAConfigMap, typhaSecrets, err = createTLS()
		if err != nil {
			return nil, fmt.Errorf("Failed to create Typha TLS: %s", err)
		}
		tcms = append(tcms, typhaCAConfigMap)
		tss = append(tss, typhaSecrets...)
	} else {
		// CA ConfigMap exists
		if len(typhaSecrets) != 2 {
			return nil, fmt.Errorf("Typha-Felix CA config map exists and so should the Secrets.")
		}
	}

	// Create copy to go into Calico Namespace
	tcm := typhaCAConfigMap.DeepCopy()
	tcm.ObjectMeta = metav1.ObjectMeta{Name: typhaCAConfigMap.Name, Namespace: CalicoNamespace}
	tcms = append(tcms, tcm)

	for _, s := range typhaSecrets {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: CalicoNamespace}
		tss = append(tss, x)
	}

	return calicoRenderer{
		installation:    cr,
		pullSecrets:     pullSecrets,
		typhaConfigMaps: tcms,
		typhaSecrets:    tss,
		birdTemplates:   bt,
		provider:        p,
		networkConfig:   nc,
	}, nil
}

func createTLS() (*corev1.ConfigMap, []*corev1.Secret, error) {
	// Make CA
	ca, err := makeCA()
	if err != nil {
		return nil, nil, err
	}
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := ca.Config.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, nil, err
	}

	// Take CA cert and create ConfigMap
	data := make(map[string]string)
	data[TyphaCABundleName] = crtContent.String()
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      TyphaCAConfigMapName,
			Namespace: OperatorNamespace(),
		},
		Data: data,
	}

	// Create TLS Secret for Felix using ca from above
	f, err := createOperatorTLSSecret(ca,
		FelixTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		[]crypto.CertificateExtensionFunc{setClientAuth},
		"typha-client")
	if err != nil {
		return nil, nil, err
	}
	// Set the CommonName used to create cert
	f.Data[CommonName] = []byte("typha-client")

	// Create TLS Secret for Felix using ca from above
	t, err := createOperatorTLSSecret(ca,
		TyphaTLSSecretName,
		TLSSecretKeyName,
		TLSSecretCertName,
		[]crypto.CertificateExtensionFunc{setServerAuth},
		"typha-server")
	if err != nil {
		return nil, nil, err
	}
	// Set the CommonName used to create cert
	t.Data[CommonName] = []byte("typha-server")

	return cm, []*corev1.Secret{f, t}, nil
}

type calicoRenderer struct {
	installation    *operator.Installation
	pullSecrets     []*corev1.Secret
	typhaConfigMaps []*corev1.ConfigMap
	typhaSecrets    []*corev1.Secret
	birdTemplates   map[string]string
	provider        operator.Provider
	networkConfig   NetworkConfig
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(r.installation))
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.provider == operator.ProviderOpenShift, r.pullSecrets))
	components = appendNotNil(components, ConfigMaps(r.typhaConfigMaps))
	components = appendNotNil(components, Secrets(r.typhaSecrets))
	components = appendNotNil(components, Typha(r.installation, r.provider))
	components = appendNotNil(components, Node(r.installation, r.provider, r.networkConfig, r.birdTemplates))
	components = appendNotNil(components, KubeControllers(r.installation))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
