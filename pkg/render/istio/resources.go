// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package istio

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var (
	//go:embed base.tgz
	baseTgz []byte
	//go:embed istiod.tgz
	istiodTgz []byte
	//go:embed cni.tgz
	cniTgz []byte
	//go:embed ztunnel.tgz
	ztunnelTgz []byte
)

type IstioResources struct {
	CRDs    []client.Object
	Base    []client.Object
	Istiod  []client.Object
	CNI     []client.Object
	ZTunnel []client.Object

	IstiodDeployment *appsv1.Deployment
	CNIDaemonSet     *appsv1.DaemonSet
	ZTunnelDaemonSet *appsv1.DaemonSet
}

type ResourceOpts struct {
	Namespace   string
	ReleaseName string

	IstiodDeploymentName      string
	IstioCNIDaemonSetName     string
	IstioZTunnelDaemonSetName string

	BaseOpts     BaseOpts
	IstiodOpts   IstiodOpts
	IstioCNIOpts IstioCNIOpts
	ZTunnelOpts  ZTunnelOpts
}

// GetResources returns istio-chart generated templates
func (r *ResourceOpts) GetResources() (*IstioResources, error) {
	var crds []client.Object

	actionConfig := new(action.Configuration)

	baseChart, err := loader.LoadArchive(bytes.NewReader(baseTgz))
	if err != nil {
		panic("Failed to load istio-base chart")
	}
	istiodChart, err := loader.LoadArchive(bytes.NewReader(istiodTgz))
	if err != nil {
		panic("Failed to load istiod chart")
	}
	cniChart, err := loader.LoadArchive(bytes.NewReader(cniTgz))
	if err != nil {
		panic("Failed to load istio-cni chart")
	}
	ztunnelChart, err := loader.LoadArchive(bytes.NewReader(ztunnelTgz))
	if err != nil {
		panic("Failed to load ztunnel chart")
	}

	client := action.NewInstall(actionConfig)
	client.DryRun = true
	client.ClientOnly = true
	client.Namespace = r.Namespace
	client.ReleaseName = r.ReleaseName

	res := &IstioResources{}
	baseOptions, _ := toMap(r.BaseOpts)
	rel, err := client.Run(baseChart, baseOptions)
	if err != nil {
		return nil, err
	}
	crds, res.Base, err = r.parseManifest(rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	istiodOptions, _ := toMap(r.IstiodOpts)
	rel, err = client.Run(istiodChart, istiodOptions)
	if err != nil {
		return nil, err
	}
	crds, res.Istiod, err = r.parseManifest(rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	cniOptions, _ := toMap(r.IstioCNIOpts)
	rel, err = client.Run(cniChart, cniOptions)
	if err != nil {
		return nil, err
	}
	crds, res.CNI, err = r.parseManifest(rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	ztunnelOptions, _ := toMap(r.ZTunnelOpts)
	rel, err = client.Run(ztunnelChart, ztunnelOptions)
	if err != nil {
		return nil, err
	}
	crds, res.ZTunnel, err = r.parseManifest(rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	return res, nil
}

type yamlKind struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func (r *ResourceOpts) parseManifest(manifest string, istRes *IstioResources) (crds, objs []client.Object, err error) {
	for _, yml := range strings.Split(manifest, "\n---\n") {
		var yamlKind yamlKind
		if err := yaml.Unmarshal([]byte(yml), &yamlKind); err != nil {
			panic(fmt.Sprintf("unable to unmarshal YAML: %v:\n%v\n", err, yml))
		}
		kindStr := yamlKind.APIVersion + "/" + yamlKind.Kind

		switch kindStr {
		case "v1/ServiceAccount":
			obj := &corev1.ServiceAccount{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "apiextensions.k8s.io/v1/CustomResourceDefinition":
			obj := &apiextv1.CustomResourceDefinition{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			crds = append(crds, obj)
		case "admissionregistration.k8s.io/v1/ValidatingWebhookConfiguration":
			obj := &admregv1.ValidatingWebhookConfiguration{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "policy/v1/PodDisruptionBudget":
			obj := &policyv1.PodDisruptionBudget{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "v1/ConfigMap":
			obj := &corev1.ConfigMap{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "rbac.authorization.k8s.io/v1/ClusterRole":
			obj := &rbacv1.ClusterRole{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "rbac.authorization.k8s.io/v1/ClusterRoleBinding":
			obj := &rbacv1.ClusterRoleBinding{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "rbac.authorization.k8s.io/v1/Role":
			obj := &rbacv1.Role{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "rbac.authorization.k8s.io/v1/RoleBinding":
			obj := &rbacv1.RoleBinding{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "v1/Service":
			obj := &corev1.Service{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "apps/v1/Deployment":
			obj := &appsv1.Deployment{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			if obj.Name == r.IstiodDeploymentName {
				istRes.IstiodDeployment = obj
			}
			objs = append(objs, obj)
		case "autoscaling/v2/HorizontalPodAutoscaler":
			obj := &autoscalingv2.HorizontalPodAutoscaler{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "admissionregistration.k8s.io/v1/MutatingWebhookConfiguration":
			obj := &admregv1.MutatingWebhookConfiguration{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "v1/ResourceQuota":
			obj := &corev1.ResourceQuota{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			objs = append(objs, obj)
		case "apps/v1/DaemonSet":
			obj := &appsv1.DaemonSet{}
			if err := yaml.Unmarshal([]byte(yml), obj); err != nil {
				panic(fmt.Sprintf("unable to unmarshal %v: %v", kindStr, err))
			}
			switch obj.Name {
			case r.IstioCNIDaemonSetName:
				istRes.CNIDaemonSet = obj
			case r.IstioZTunnelDaemonSetName:
				istRes.ZTunnelDaemonSet = obj
			}
			objs = append(objs, obj)
		case "/":
			// Ignore empty documents.
		default:
			panic(fmt.Sprintf("unhandled type %v", kindStr))
		}
	}
	return crds, objs, nil
}
