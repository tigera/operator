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

package datastoremigration

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	SchemeGroupVersion = schema.GroupVersion{Group: "migration.projectcalico.org", Version: "v1beta1"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&DatastoreMigration{},
		&DatastoreMigrationList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// DatastoreMigration is a minimal stub for the migration.projectcalico.org/v1beta1
// DatastoreMigration CR. It contains only the fields the operator needs to read,
// allowing controller-runtime to cache these objects via a typed watch.
type DatastoreMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            DatastoreMigrationStatus `json:"status,omitempty"`
}

type DatastoreMigrationStatus struct {
	Phase string `json:"phase,omitempty"`
}

func (in *DatastoreMigration) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(DatastoreMigration)
	in.DeepCopyInto(&out.ObjectMeta)
	out.TypeMeta = in.TypeMeta
	out.Status = in.Status
	return out
}

// DatastoreMigrationList is a list of DatastoreMigration resources.
type DatastoreMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DatastoreMigration `json:"items"`
}

func (in *DatastoreMigrationList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(DatastoreMigrationList)
	out.TypeMeta = in.TypeMeta
	in.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]DatastoreMigration, len(in.Items))
		for i := range in.Items {
			item := in.Items[i].DeepCopyObject().(*DatastoreMigration)
			out.Items[i] = *item
		}
	}
	return out
}
