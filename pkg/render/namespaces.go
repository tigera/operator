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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
)

func Namespaces(installation *operatorv1.InstallationSpec, pullSecrets []*corev1.Secret) Component {
	return &namespaceComponent{
		installation: installation,
		pullSecrets:  pullSecrets,
	}
}

type namespaceComponent struct {
	installation *operatorv1.InstallationSpec
	pullSecrets  []*corev1.Secret
}

func (c *namespaceComponent) SupportedOSType() OSType {
	return OSTypeAny
}

func (c *namespaceComponent) Objects() ([]runtime.Object, []runtime.Object) {
	ns := []runtime.Object{
		createNamespace(common.CalicoNamespace, c.installation.KubernetesProvider == operatorv1.ProviderOpenShift),
	}
	if c.installation.Variant == operatorv1.TigeraSecureEnterprise {
		// We need to always have ns tigera-dex even when the Authentication CR is not present, so policies can be added to this namespace.
		ns = append(ns, createNamespace(DexObjectName, c.installation.KubernetesProvider == operatorv1.ProviderOpenShift))
	}
	if len(c.pullSecrets) > 0 {
		ns = append(ns, copyImagePullSecrets(c.pullSecrets, common.CalicoNamespace)...)
	}

	return ns, nil
}

func (c *namespaceComponent) Ready() bool {
	return true
}

func createNamespace(name string, openshift bool) *corev1.Namespace {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{"name": name},
			Annotations: map[string]string{},
		},
	}

	// OpenShift requires special labels and annotations.
	if openshift {
		ns.Labels["openshift.io/run-level"] = "0"
		ns.Annotations["openshift.io/node-selector"] = ""
	}
	return ns
}
