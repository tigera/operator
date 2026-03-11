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

package fieldowner_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/controller/utils/fieldowner"
)

// newObj creates a minimal client.Object for testing with optional annotations.
func newObj(annotations map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: annotations,
		},
	}
}

var _ = Describe("Tracker", func() {
	Context("ForObject", func() {
		It("should handle an object with no annotations", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			Expect(t.ManagedFields()).To(BeEmpty())
		})

		It("should load existing tracked fields from annotation", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"Foo":"bar","Baz":"123"}`,
			})
			t := fieldowner.ForObject("test", obj)
			Expect(t.ManagedFields()).To(Equal(map[string]string{
				"Foo": "bar",
				"Baz": "123",
			}))
		})

		It("should isolate trackers by controller name", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-alpha": `{"F1":"a"}`,
				"operator.tigera.io/managed-fields-beta":  `{"F2":"b"}`,
			})
			tAlpha := fieldowner.ForObject("alpha", obj)
			tBeta := fieldowner.ForObject("beta", obj)
			Expect(tAlpha.IsManaged("F1")).To(BeTrue())
			Expect(tAlpha.IsManaged("F2")).To(BeFalse())
			Expect(tBeta.IsManaged("F1")).To(BeFalse())
			Expect(tBeta.IsManaged("F2")).To(BeTrue())
		})
	})

	Context("ConflictError policy", func() {
		It("should set an untracked field with no current value", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "", "desired", fieldowner.ConflictError)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())
		})

		It("should adopt an untracked field whose current value matches desired", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "val", "val", fieldowner.ConflictError)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())

			// Should now be tracked.
			Expect(t.IsManaged("F")).To(BeTrue())
		})

		It("should error on an untracked field whose current value differs from desired", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			_, err := t.Manage("F", "user-val", "desired", fieldowner.ConflictError)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("refusing to override"))
		})

		It("should not set a tracked field that already has the desired value", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"val"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "val", "val", fieldowner.ConflictError)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())
		})

		It("should update a tracked field to a new desired value", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"old"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "old", "new", fieldowner.ConflictError)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())

			t.Flush(obj)
			Expect(obj.Annotations["operator.tigera.io/managed-fields-test"]).To(ContainSubstring(`"F":"new"`))
		})

		It("should error when a tracked field was modified by a user", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"operator-set"}`,
			})
			t := fieldowner.ForObject("test", obj)
			_, err := t.Manage("F", "user-changed", "operator-set", fieldowner.ConflictError)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("modified by another actor"))
		})
	})

	Context("ConflictDefer policy", func() {
		It("should set an untracked field with no current value", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "", "default-val", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())
		})

		It("should not claim an untracked field that already has a value", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "existing", "default-val", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())
			Expect(t.IsManaged("F")).To(BeFalse())
		})

		It("should release ownership when user modifies a tracked field", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"operator-default"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "user-changed", "operator-default", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())
			Expect(t.IsManaged("F")).To(BeFalse())
		})

		It("should not re-set a tracked field that already has the desired value", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"val"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "val", "val", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())
		})

		It("should update a tracked field to a new desired value when not user-modified", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"old"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "old", "new", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())
		})
	})

	Context("ConflictOverride policy", func() {
		It("should always set when values differ", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"operator-set"}`,
			})
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "user-changed", "operator-wants", fieldowner.ConflictOverride)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())
		})

		It("should not set when current equals desired", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			shouldSet, err := t.Manage("F", "val", "val", fieldowner.ConflictOverride)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse())
		})
	})

	Context("Release", func() {
		It("should remove a tracked field", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"val","G":"other"}`,
			})
			t := fieldowner.ForObject("test", obj)
			t.Release("F")
			Expect(t.IsManaged("F")).To(BeFalse())
			Expect(t.IsManaged("G")).To(BeTrue())
		})

		It("should be a no-op for untracked fields", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			t.Release("nonexistent")
			Expect(t.ManagedFields()).To(BeEmpty())
		})
	})

	Context("Flush", func() {
		It("should write tracked fields to the annotation", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)
			_, _ = t.Manage("A", "", "1", fieldowner.ConflictError)
			_, _ = t.Manage("B", "", "2", fieldowner.ConflictError)
			t.Flush(obj)

			Expect(obj.Annotations).To(HaveKey("operator.tigera.io/managed-fields-test"))
			var fields map[string]string
			Expect(json.Unmarshal([]byte(obj.Annotations["operator.tigera.io/managed-fields-test"]), &fields)).To(Succeed())
			Expect(fields).To(Equal(map[string]string{"A": "1", "B": "2"}))
		})

		It("should remove the annotation when no fields are tracked", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"F":"val"}`,
			})
			t := fieldowner.ForObject("test", obj)
			t.Release("F")
			t.Flush(obj)
			Expect(obj.Annotations).NotTo(HaveKey("operator.tigera.io/managed-fields-test"))
		})

		It("should preserve other annotations", func() {
			obj := newObj(map[string]string{
				"other-annotation": "keep-me",
			})
			t := fieldowner.ForObject("test", obj)
			_, _ = t.Manage("F", "", "val", fieldowner.ConflictError)
			t.Flush(obj)
			Expect(obj.Annotations["other-annotation"]).To(Equal("keep-me"))
			Expect(obj.Annotations).To(HaveKey("operator.tigera.io/managed-fields-test"))
		})
	})

	Context("MigrateAnnotation", func() {
		It("should migrate a legacy annotation into the tracker", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/bpfEnabled": "true",
			})
			t := fieldowner.ForObject("test", obj)
			t.MigrateAnnotation(obj, "BPFEnabled", "operator.tigera.io/bpfEnabled")

			Expect(t.IsManaged("BPFEnabled")).To(BeTrue())
			Expect(t.ManagedFields()["BPFEnabled"]).To(Equal("true"))
			// Old annotation should be removed.
			Expect(obj.Annotations).NotTo(HaveKey("operator.tigera.io/bpfEnabled"))
		})

		It("should not overwrite an existing tracked value", func() {
			obj := newObj(map[string]string{
				"operator.tigera.io/managed-fields-test": `{"BPFEnabled":"false"}`,
				"operator.tigera.io/bpfEnabled":          "true",
			})
			t := fieldowner.ForObject("test", obj)
			t.MigrateAnnotation(obj, "BPFEnabled", "operator.tigera.io/bpfEnabled")

			// Should keep the existing tracked value, not the legacy one.
			Expect(t.ManagedFields()["BPFEnabled"]).To(Equal("false"))
			// But the old annotation should still be removed.
			Expect(obj.Annotations).NotTo(HaveKey("operator.tigera.io/bpfEnabled"))
		})

		It("should be a no-op when the legacy annotation doesn't exist", func() {
			obj := newObj(map[string]string{"other": "val"})
			t := fieldowner.ForObject("test", obj)
			t.MigrateAnnotation(obj, "BPFEnabled", "operator.tigera.io/bpfEnabled")
			Expect(t.IsManaged("BPFEnabled")).To(BeFalse())
		})
	})

	Context("FormatValue", func() {
		It("should return empty string for nil", func() {
			Expect(fieldowner.FormatValue(nil)).To(Equal(""))
		})

		It("should return empty string for nil pointer", func() {
			var p *bool
			Expect(fieldowner.FormatValue(p)).To(Equal(""))
		})

		It("should format bool pointer", func() {
			v := true
			Expect(fieldowner.FormatValue(&v)).To(Equal("true"))
		})

		It("should format int pointer", func() {
			v := 9099
			Expect(fieldowner.FormatValue(&v)).To(Equal("9099"))
		})

		It("should format string value", func() {
			Expect(fieldowner.FormatValue("Enabled")).To(Equal("Enabled"))
		})

		It("should format struct as JSON", func() {
			type Range struct {
				Min int `json:"min"`
				Max int `json:"max"`
			}
			r := Range{Min: 65, Max: 99}
			Expect(fieldowner.FormatValue(r)).To(Equal(`{"min":65,"max":99}`))
		})
	})

	Context("multiple fields in one tracker", func() {
		It("should independently track multiple fields", func() {
			obj := newObj(nil)
			t := fieldowner.ForObject("test", obj)

			shouldSet, err := t.Manage("A", "", "1", fieldowner.ConflictError)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())

			shouldSet, err = t.Manage("B", "", "2", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeTrue())

			shouldSet, err = t.Manage("C", "existing", "3", fieldowner.ConflictDefer)
			Expect(err).NotTo(HaveOccurred())
			Expect(shouldSet).To(BeFalse()) // defers to existing

			t.Flush(obj)

			var fields map[string]string
			Expect(json.Unmarshal([]byte(obj.Annotations["operator.tigera.io/managed-fields-test"]), &fields)).To(Succeed())
			Expect(fields).To(Equal(map[string]string{"A": "1", "B": "2"}))
		})
	})
})
