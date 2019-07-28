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
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	calicoNamespace           = "calico-system"
	tigeraSecureNamespace     = "tigera-system"
	calicoMonitoringNamespace = "calico-monitoring"
)

func Namespaces(cr *operator.Installation, openshift bool) Component {
	return &namespaceComponent{cr: cr, openshift: openshift}
}

type namespaceComponent struct {
	cr        *operator.Installation
	openshift bool
}

func (c *namespaceComponent) GetObjects() []runtime.Object {
	ns := []runtime.Object{
		c.createNamespace(calicoNamespace),
	}

	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		ns = append(ns, c.createNamespace(tigeraSecureNamespace))
		ns = append(ns, c.createNamespace(calicoMonitoringNamespace))
	}
	return ns
}

func (c *namespaceComponent) GetComponentDeps() []runtime.Object {
	return nil
}

func (c *namespaceComponent) Ready() bool {
	return true
}

func (c *namespaceComponent) createNamespace(name string) *v1.Namespace {
	ns := &v1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{"name": name},
			Annotations: map[string]string{},
		},
	}

	// OpenShift requires special labels and annotations.
	if c.openshift {
		ns.Labels["openshift.io/run-level"] = "0"
		ns.Annotations["openshift.io/node-selector"] = ""
	}
	return ns
}
