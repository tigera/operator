// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package istio_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/tigera/operator/pkg/render/istio"
)

var _ = Describe("L7 Waypoint render", func() {
	const (
		ns    = "calico-system"
		image = "my-registry.example.com/tigera/l7-collector:v0.0.0"
	)

	It("EnvoyFilterGVK returns networking.istio.io/v1alpha3", func() {
		gvk := istio.EnvoyFilterGVK()
		Expect(gvk.Group).To(Equal("networking.istio.io"))
		Expect(gvk.Version).To(Equal("v1alpha3"))
		Expect(gvk.Kind).To(Equal("EnvoyFilter"))
	})

	Context("L7WaypointObjects", func() {
		It("returns exactly three resources in the requested namespace", func() {
			objs := istio.L7WaypointObjects(ns, image)
			Expect(objs).To(HaveLen(3))
			for _, o := range objs {
				Expect(o.GetNamespace()).To(Equal(ns), "object %s/%s in wrong namespace", o.GetObjectKind().GroupVersionKind().Kind, o.GetName())
			}
		})

		It("returns the three expected resource names", func() {
			objs := istio.L7WaypointObjects(ns, image)
			names := map[string]bool{}
			for _, o := range objs {
				names[o.GetName()] = true
			}
			Expect(names).To(HaveKey(istio.L7WaypointDefaultsConfigMapName))
			Expect(names).To(HaveKey(istio.L7WaypointALSFilterName))
			Expect(names).To(HaveKey(istio.L7WaypointSrcPortFilterName))
		})
	})

	Context("defaults ConfigMap", func() {
		var cm *corev1.ConfigMap
		BeforeEach(func() {
			objs := istio.L7WaypointObjects(ns, image)
			var ok bool
			cm, ok = objs[0].(*corev1.ConfigMap)
			Expect(ok).To(BeTrue(), "first object should be the defaults ConfigMap")
		})

		It("is labelled for the istio-waypoint GatewayClass", func() {
			Expect(cm.Labels).To(HaveKeyWithValue(
				"gateway.istio.io/defaults-for-class", istio.IstioWaypointGatewayClass))
		})

		It("embeds the provided l7-collector image with --mode=waypoint", func() {
			raw, ok := cm.Data["deployment"]
			Expect(ok).To(BeTrue(), "ConfigMap must contain a `deployment` key")

			var overlay map[string]interface{}
			Expect(yaml.Unmarshal([]byte(raw), &overlay)).To(Succeed())

			containers := diveContainers(overlay)
			var found bool
			for _, c := range containers {
				m := c.(map[string]interface{})
				if m["name"] == "l7-collector" {
					found = true
					Expect(m["image"]).To(Equal(image))
					args := m["args"].([]interface{})
					Expect(args).To(ContainElement("--mode=waypoint"))
				}
			}
			Expect(found).To(BeTrue(), "overlay must contain an l7-collector sidecar container")
		})

		It("adds the shared socket volumeMount to the istio-proxy container", func() {
			var overlay map[string]interface{}
			Expect(yaml.Unmarshal([]byte(cm.Data["deployment"]), &overlay)).To(Succeed())
			containers := diveContainers(overlay)

			var found bool
			for _, c := range containers {
				m := c.(map[string]interface{})
				if m["name"] != "istio-proxy" {
					continue
				}
				found = true
				mounts := m["volumeMounts"].([]interface{})
				Expect(mounts).To(HaveLen(1))
				mount := mounts[0].(map[string]interface{})
				Expect(mount["name"]).To(Equal("l7-collector-socket"))
				Expect(mount["mountPath"]).To(Equal("/var/run/l7-collector"))
			}
			Expect(found).To(BeTrue(), "overlay must patch the istio-proxy container")
		})

		It("declares the emptyDir and Felix CSI volumes", func() {
			var overlay map[string]interface{}
			Expect(yaml.Unmarshal([]byte(cm.Data["deployment"]), &overlay)).To(Succeed())
			volumes := diveVolumes(overlay)

			var hasSocket, hasFelix bool
			for _, v := range volumes {
				m := v.(map[string]interface{})
				switch m["name"] {
				case "l7-collector-socket":
					hasSocket = true
					Expect(m).To(HaveKey("emptyDir"))
				case "felix-sync":
					hasFelix = true
					csi := m["csi"].(map[string]interface{})
					Expect(csi["driver"]).To(Equal("csi.tigera.io"))
				}
			}
			Expect(hasSocket).To(BeTrue(), "overlay must declare the l7-collector-socket emptyDir volume")
			Expect(hasFelix).To(BeTrue(), "overlay must declare the felix-sync CSI volume")
		})
	})

	Context("ALS EnvoyFilter", func() {
		var ef *istio.EnvoyFilter
		BeforeEach(func() {
			objs := istio.L7WaypointObjects(ns, image)
			var ok bool
			ef, ok = objs[1].(*istio.EnvoyFilter)
			Expect(ok).To(BeTrue())
			Expect(ef.Kind).To(Equal("EnvoyFilter"))
			Expect(ef.Name).To(Equal(istio.L7WaypointALSFilterName))
		})

		It("attaches to the istio-waypoint GatewayClass", func() {
			refs := ef.Spec["targetRefs"].([]interface{})
			Expect(refs).To(HaveLen(1))
			ref := refs[0].(map[string]interface{})
			Expect(ref).To(HaveKeyWithValue("kind", "GatewayClass"))
			Expect(ref).To(HaveKeyWithValue("group", "gateway.networking.k8s.io"))
			Expect(ref).To(HaveKeyWithValue("name", istio.IstioWaypointGatewayClass))
		})

		It("patches the main_internal listener", func() {
			patch := firstConfigPatch(ef)
			listener := patch["match"].(map[string]interface{})["listener"].(map[string]interface{})
			Expect(listener["name"]).To(Equal("main_internal"))
		})

		It("configures the l7-collector unix socket as gRPC ALS target", func() {
			patch := firstConfigPatch(ef)
			value := patch["patch"].(map[string]interface{})["value"].(map[string]interface{})
			typedConfig := value["typed_config"].(map[string]interface{})
			accessLog := typedConfig["access_log"].([]interface{})[0].(map[string]interface{})
			common := accessLog["typed_config"].(map[string]interface{})["common_config"].(map[string]interface{})
			grpc := common["grpc_service"].(map[string]interface{})["google_grpc"].(map[string]interface{})
			Expect(grpc["target_uri"]).To(Equal("unix:///var/run/l7-collector/l7-collector.sock"))
		})
	})

	Context("SrcPort EnvoyFilter", func() {
		var ef *istio.EnvoyFilter
		BeforeEach(func() {
			objs := istio.L7WaypointObjects(ns, image)
			var ok bool
			ef, ok = objs[2].(*istio.EnvoyFilter)
			Expect(ok).To(BeTrue())
			Expect(ef.Kind).To(Equal("EnvoyFilter"))
			Expect(ef.Name).To(Equal(istio.L7WaypointSrcPortFilterName))
		})

		It("attaches to the istio-waypoint GatewayClass", func() {
			refs := ef.Spec["targetRefs"].([]interface{})
			Expect(refs).To(HaveLen(1))
			ref := refs[0].(map[string]interface{})
			Expect(ref).To(HaveKeyWithValue("kind", "GatewayClass"))
			Expect(ref).To(HaveKeyWithValue("group", "gateway.networking.k8s.io"))
			Expect(ref).To(HaveKeyWithValue("name", istio.IstioWaypointGatewayClass))
		})

		It("inserts after connect_authority on the connect_terminate listener", func() {
			patch := firstConfigPatch(ef)
			listener := patch["match"].(map[string]interface{})["listener"].(map[string]interface{})
			Expect(listener["name"]).To(Equal("connect_terminate"))
			subFilter := listener["filterChain"].(map[string]interface{})["filter"].(map[string]interface{})["subFilter"].(map[string]interface{})
			Expect(subFilter["name"]).To(Equal("connect_authority"))
			Expect(patch["patch"].(map[string]interface{})["operation"]).To(Equal("INSERT_AFTER"))
		})

		It("propagates io.tigera.forwarded_header to upstream", func() {
			patch := firstConfigPatch(ef)
			value := patch["patch"].(map[string]interface{})["value"].(map[string]interface{})
			typedConfig := value["typed_config"].(map[string]interface{})
			onReq := typedConfig["on_request_headers"].([]interface{})[0].(map[string]interface{})
			Expect(onReq["object_key"]).To(Equal("io.tigera.forwarded_header"))
			Expect(onReq["shared_with_upstream"]).To(Equal("ONCE"))
		})
	})
})

// diveContainers returns the containers slice from a strategic merge overlay
// shaped like {spec: {template: {spec: {containers: [...]}}}}.
func diveContainers(overlay map[string]interface{}) []interface{} {
	return overlay["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})
}

// diveVolumes returns the volumes slice from the same overlay shape.
func diveVolumes(overlay map[string]interface{}) []interface{} {
	return overlay["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["volumes"].([]interface{})
}

// firstConfigPatch returns the first entry in spec.configPatches of an
// EnvoyFilter.
func firstConfigPatch(ef *istio.EnvoyFilter) map[string]interface{} {
	patches := ef.Spec["configPatches"].([]interface{})
	Expect(patches).NotTo(BeEmpty())
	return patches[0].(map[string]interface{})
}
