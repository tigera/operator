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

// Package datastoremigration provides utilities for checking DatastoreMigration
// CR state from the operator's controllers.
package datastoremigration

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/tigera/operator/pkg/ctrlruntime"
)

var log = logf.Log.WithName("datastoremigration")

// GVR is the GroupVersionResource for DatastoreMigration CRs.
var GVR = schema.GroupVersionResource{
	Group:    "migration.projectcalico.org",
	Version:  "v1beta1",
	Resource: "datastoremigrations",
}

// Phase constants for DatastoreMigration status.
const (
	PhasePending                      = "Pending"
	PhaseMigrating                    = "Migrating"
	PhaseWaitingForConflictResolution = "WaitingForConflictResolution"
	PhaseConverged                    = "Converged"
	PhaseComplete                     = "Complete"
	PhaseFailed                       = "Failed"
)

// GetPhase returns the phase of the first DatastoreMigration CR, or empty
// string if none exists or the CRD is not installed.
func GetPhase(cfg *rest.Config) string {
	if cfg == nil {
		return ""
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return ""
	}
	list, err := dc.Resource(GVR).List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil || len(list.Items) == 0 {
		return ""
	}
	status, ok := list.Items[0].Object["status"].(map[string]any)
	if !ok {
		return ""
	}
	phase, ok := status["phase"].(string)
	if !ok {
		return ""
	}
	return phase
}

// Exists returns true if at least one DatastoreMigration CR exists.
func Exists(cfg *rest.Config) bool {
	return GetPhase(cfg) != "" || existsWithoutPhase(cfg)
}

// existsWithoutPhase checks if a CR exists even if it has no phase set yet
// (e.g., just created, Pending with empty status).
func existsWithoutPhase(cfg *rest.Config) bool {
	if cfg == nil {
		return false
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return false
	}
	list, err := dc.Resource(GVR).List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		return false
	}
	return len(list.Items) > 0
}

// WaitForWatchAndAdd polls for the DatastoreMigration CRD and sets up a watch
// on the given controller once available. This triggers controller reconciliation
// when the migration phase changes.
func WaitForWatchAndAdd(c ctrlruntime.Controller, cs *kubernetes.Clientset) {
	duration := 1 * time.Second
	maxDuration := 30 * time.Second
	for {
		time.Sleep(duration)
		duration = min(2*duration, maxDuration)

		_, err := cs.Discovery().ServerResourcesForGroupVersion("migration.projectcalico.org/v1beta1")
		if err != nil {
			continue
		}

		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "migration.projectcalico.org",
			Version: "v1beta1",
			Kind:    "DatastoreMigration",
		})
		if err := c.WatchObject(obj, &handler.EnqueueRequestForObject{}); err != nil {
			log.V(2).Info("Failed to watch DatastoreMigration, will retry", "error", err)
			continue
		}
		log.Info("Successfully watching DatastoreMigration CRs")
		return
	}
}
