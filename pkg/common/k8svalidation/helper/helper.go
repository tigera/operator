/*
Copyright (c) 2022 Tigera, Inc. All rights reserved.

Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The contents of this file are mostly copied, with minor modifications, from:
https://github.com/kubernetes/kubernetes/blob/f38615fb9d1188934213633ff92d523259ae8f6a/pkg/apis/core/helper/helpers.go
*/

package helper

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"

	// "k8s.io/kubernetes/pkg/apis/core"
	core "k8s.io/api/core/v1"
)

// IsHugePageResourceName returns true if the resource name has the huge page
// resource prefix.
func IsHugePageResourceName(name core.ResourceName) bool {
	return strings.HasPrefix(string(name), core.ResourceHugePagesPrefix)
}

// IsQuotaHugePageResourceName returns true if the resource name has the quota
// related huge page resource prefix.
func IsQuotaHugePageResourceName(name core.ResourceName) bool {
	return strings.HasPrefix(string(name), core.ResourceHugePagesPrefix) || strings.HasPrefix(string(name), core.ResourceRequestsHugePagesPrefix)
}

// Semantic can do semantic deep equality checks for core objects.
// Example: apiequality.Semantic.DeepEqual(aPod, aPodWithNonNilButEmptyMaps) == true
var Semantic = conversion.EqualitiesOrDie(
	func(a, b resource.Quantity) bool {
		// Ignore formatting, only care that numeric value stayed the same.
		// TODO: if we decide it's important, it should be safe to start comparing the format.
		//
		// Uninitialized quantities are equivalent to 0 quantities.
		return a.Cmp(b) == 0
	},
	func(a, b metav1.MicroTime) bool {
		return a.UTC() == b.UTC()
	},
	func(a, b metav1.Time) bool {
		return a.UTC() == b.UTC()
	},
	func(a, b labels.Selector) bool {
		return a.String() == b.String()
	},
	func(a, b fields.Selector) bool {
		return a.String() == b.String()
	},
)

var standardContainerResources = sets.NewString(
	string(core.ResourceCPU),
	string(core.ResourceMemory),
	string(core.ResourceEphemeralStorage),
)

// IsStandardContainerResourceName returns true if the container can make a resource request
// for the specified resource
func IsStandardContainerResourceName(str string) bool {
	return standardContainerResources.Has(str) || IsHugePageResourceName(core.ResourceName(str))
}

// IsExtendedResourceName returns true if:
// 1. the resource name is not in the default namespace;
// 2. resource name does not have "requests." prefix,
// to avoid confusion with the convention in quota
// 3. it satisfies the rules in IsQualifiedName() after converted into quota resource name
func IsExtendedResourceName(name core.ResourceName) bool {
	if IsNativeResource(name) || strings.HasPrefix(string(name), core.DefaultResourceRequestsPrefix) {
		return false
	}
	// Ensure it satisfies the rules in IsQualifiedName() after converted into quota resource name
	nameForQuota := fmt.Sprintf("%s%s", core.DefaultResourceRequestsPrefix, string(name))
	if errs := validation.IsQualifiedName(string(nameForQuota)); len(errs) != 0 {
		return false
	}
	return true
}

// IsNativeResource returns true if the resource name is in the
// *kubernetes.io/ namespace. Partially-qualified (unprefixed) names are
// implicitly in the kubernetes.io/ namespace.
func IsNativeResource(name core.ResourceName) bool {
	return !strings.Contains(string(name), "/") ||
		strings.Contains(string(name), core.ResourceDefaultNamespacePrefix)
}

var standardResources = sets.NewString(
	string(core.ResourceCPU),
	string(core.ResourceMemory),
	string(core.ResourceEphemeralStorage),
	string(core.ResourceRequestsCPU),
	string(core.ResourceRequestsMemory),
	string(core.ResourceRequestsEphemeralStorage),
	string(core.ResourceLimitsCPU),
	string(core.ResourceLimitsMemory),
	string(core.ResourceLimitsEphemeralStorage),
	string(core.ResourcePods),
	string(core.ResourceQuotas),
	string(core.ResourceServices),
	string(core.ResourceReplicationControllers),
	string(core.ResourceSecrets),
	string(core.ResourceConfigMaps),
	string(core.ResourcePersistentVolumeClaims),
	string(core.ResourceStorage),
	string(core.ResourceRequestsStorage),
	string(core.ResourceServicesNodePorts),
	string(core.ResourceServicesLoadBalancers),
)

// IsStandardResourceName returns true if the resource is known to the system
func IsStandardResourceName(str string) bool {
	return standardResources.Has(str) || IsQuotaHugePageResourceName(core.ResourceName(str))
}

var integerResources = sets.NewString(
	string(core.ResourcePods),
	string(core.ResourceQuotas),
	string(core.ResourceServices),
	string(core.ResourceReplicationControllers),
	string(core.ResourceSecrets),
	string(core.ResourceConfigMaps),
	string(core.ResourcePersistentVolumeClaims),
	string(core.ResourceServicesNodePorts),
	string(core.ResourceServicesLoadBalancers),
)

// IsIntegerResourceName returns true if the resource is measured in integer values
func IsIntegerResourceName(str string) bool {
	return integerResources.Has(str) || IsExtendedResourceName(core.ResourceName(str))
}

// IsServiceIPSet aims to check if the service's ClusterIP is set or not
// the objective is not to perform validation here
func IsServiceIPSet(service *core.Service) bool {
	// This function assumes that the service is semantically validated
	// it does not test if the IP is valid, just makes sure that it is set.
	return len(service.Spec.ClusterIP) > 0 &&
		service.Spec.ClusterIP != core.ClusterIPNone
}

var standardFinalizers = sets.NewString(
	string(core.FinalizerKubernetes),
	metav1.FinalizerOrphanDependents,
	metav1.FinalizerDeleteDependents,
)

func ContainsAccessMode(modes []core.PersistentVolumeAccessMode, mode core.PersistentVolumeAccessMode) bool {
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

// NodeSelectorRequirementsAsSelector converts the []NodeSelectorRequirement core type into a struct that implements
// labels.Selector.
func NodeSelectorRequirementsAsSelector(nsm []core.NodeSelectorRequirement) (labels.Selector, error) {
	if len(nsm) == 0 {
		return labels.Nothing(), nil
	}
	selector := labels.NewSelector()
	for _, expr := range nsm {
		var op selection.Operator
		switch expr.Operator {
		case core.NodeSelectorOpIn:
			op = selection.In
		case core.NodeSelectorOpNotIn:
			op = selection.NotIn
		case core.NodeSelectorOpExists:
			op = selection.Exists
		case core.NodeSelectorOpDoesNotExist:
			op = selection.DoesNotExist
		case core.NodeSelectorOpGt:
			op = selection.GreaterThan
		case core.NodeSelectorOpLt:
			op = selection.LessThan
		default:
			return nil, fmt.Errorf("%q is not a valid node selector operator", expr.Operator)
		}
		r, err := labels.NewRequirement(expr.Key, op, expr.Values)
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*r)
	}
	return selector, nil
}

func toResourceNames(resources core.ResourceList) []core.ResourceName {
	result := []core.ResourceName{}
	for resourceName := range resources {
		result = append(result, resourceName)
	}
	return result
}

func toSet(resourceNames []core.ResourceName) sets.String {
	result := sets.NewString()
	for _, resourceName := range resourceNames {
		result.Insert(string(resourceName))
	}
	return result
}

// toContainerResourcesSet returns a set of resources names in container resource requirements
func toContainerResourcesSet(ctr *core.Container) sets.String {
	resourceNames := toResourceNames(ctr.Resources.Requests)
	resourceNames = append(resourceNames, toResourceNames(ctr.Resources.Limits)...)
	return toSet(resourceNames)
}

func validFirstDigit(str string) bool {
	if len(str) == 0 {
		return false
	}
	return str[0] == '-' || (str[0] == '0' && str == "0") || (str[0] >= '1' && str[0] <= '9')
}
