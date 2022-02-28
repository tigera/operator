// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package apis

import (
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	configv1 "github.com/openshift/api/config/v1"
	ocsv1 "github.com/openshift/api/security/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	tigera "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	aggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, operator.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, configv1.Install)
	AddToSchemes = append(AddToSchemes, aggregator.AddToScheme)
	AddToSchemes = append(AddToSchemes, apiextensions.AddToScheme)
	AddToSchemes = append(AddToSchemes, tigera.AddToScheme)
	AddToSchemes = append(AddToSchemes, ocsv1.AddToScheme)
	AddToSchemes = append(AddToSchemes, esv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, kbv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, policyv1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, policyv1beta1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, monitoringv1.SchemeBuilder.AddToScheme)
}
