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
	"fmt"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func CustomResourceDefinitions(cr *operator.Installation) Component {
	return &crdComponent{cr: cr}
}

type crdComponent struct {
	cr *operator.Installation
}

func (c *crdComponent) Objects() []runtime.Object {
	crds := c.calicoCRDs()
	if c.cr.Spec.Variant == operator.TigeraSecureEnterprise {
		crds = append(crds, tigeraSecureCRDs()...)
	}
	return crds
}

func (c *crdComponent) Ready() bool {
	return true
}

type desiredCRD struct {
	scope apiextensions.ResourceScope
	names apiextensions.CustomResourceDefinitionNames
}

func (c *crdComponent) calicoCRDs() []runtime.Object {
	desiredNames := []desiredCRD{
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "bgpconfigurations",
				Singular: "bgpconfiguration",
				Kind:     "BGPConfiguration",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "bgppeers",
				Singular: "bgppeer",
				Kind:     "BGPPeer",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "blockaffinities",
				Singular: "blockaffinity",
				Kind:     "BlockAffinity",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "clusterinformations",
				Singular: "clusterinformation",
				Kind:     "ClusterInformation",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "felixconfigurations",
				Singular: "felixconfiguration",
				Kind:     "FelixConfiguration",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalnetworkpolicies",
				Singular: "globalnetworkpolicy",
				Kind:     "GlobalNetworkPolicy",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalnetworksets",
				Singular: "globalnetworkset",
				Kind:     "GlobalNetworkSet",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "hostendpoints",
				Singular: "hostendpoint",
				Kind:     "HostEndpoint",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "ipamblocks",
				Singular: "ipamblock",
				Kind:     "IPAMBlock",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "ipamconfigs",
				Singular: "ipamconfig",
				Kind:     "IPAMConfig",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "ipamhandles",
				Singular: "ipamhandle",
				Kind:     "IPAMHandle",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "ippools",
				Singular: "ippool",
				Kind:     "IPPool",
			},
		},
		{
			scope: apiextensions.NamespaceScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "networksets",
				Singular: "networkset",
				Kind:     "NetworkSet",
			},
		},
		{
			scope: apiextensions.NamespaceScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "networkpolicies",
				Singular: "networkpolicy",
				Kind:     "NetworkPolicy",
			},
		},
	}

	crds := []runtime.Object{}
	for _, names := range desiredNames {
		crds = append(crds, buildCRD(names))
	}
	return crds
}

func tigeraSecureCRDs() []runtime.Object {
	desiredNames := []desiredCRD{
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalalerts",
				Singular: "globalalert",
				Kind:     "GlobalAlert",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalreports",
				Singular: "globalreport",
				Kind:     "GlobalReport",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalreporttypes",
				Singular: "globalreporttype",
				Kind:     "GlobalReportType",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "globalthreatfeeds",
				Singular: "globalthreatfeed",
				Kind:     "GlobalThreatFeed",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "licensekeys",
				Singular: "licensekey",
				Kind:     "LicenseKey",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "remoteclusterconfigurations",
				Singular: "remoteclusterconfiguration",
				Kind:     "RemoteClusterConfiguration",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "managedclusters",
				Singular: "managedcluster",
				Kind:     "ManagedCluster",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "stagedglobalnetworkpolicies",
				Singular: "stagedglobalnetworkpolicy",
				Kind:     "StagedGlobalNetworkPolicy",
			},
		},
		{
			scope: apiextensions.NamespaceScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "stagedkubernetesnetworkpolicies",
				Singular: "stagedkubernetesnetworkpolicy",
				Kind:     "StagedKubernetesNetworkPolicy",
			},
		},
		{
			scope: apiextensions.NamespaceScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "stagednetworkpolicies",
				Singular: "stagednetworkpolicy",
				Kind:     "StagedNetworkPolicy",
			},
		},
		{
			scope: apiextensions.ClusterScoped,
			names: apiextensions.CustomResourceDefinitionNames{
				Plural:   "tiers",
				Singular: "tier",
				Kind:     "Tier",
			},
		},
	}

	crds := []runtime.Object{}
	for _, names := range desiredNames {
		crds = append(crds, buildCRD(names))
	}
	return crds
}

func buildCRD(d desiredCRD) runtime.Object {
	return &apiextensions.CustomResourceDefinition{
		TypeMeta:   metav1.TypeMeta{Kind: "CustomResourceDefinition", APIVersion: "v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s.crd.projectcalico.org", d.names.Plural)},
		Spec: apiextensions.CustomResourceDefinitionSpec{
			Scope: d.scope,
			Group: "crd.projectcalico.org",
			Versions: []apiextensions.CustomResourceDefinitionVersion{
				{Name: "v1", Served: true, Storage: true},
			},
			Names: d.names,
		},
	}
}
