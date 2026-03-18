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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/ctrlruntime"
)

var log = logf.Log.WithName("datastoremigration")

// Phase constants for DatastoreMigration status.
const (
	PhasePending                      = "Pending"
	PhaseMigrating                    = "Migrating"
	PhaseWaitingForConflictResolution = "WaitingForConflictResolution"
	PhaseConverged                    = "Converged"
	PhaseComplete                     = "Complete"
	PhaseFailed                       = "Failed"
)

// get fetches the first DatastoreMigration CR and returns its phase and
// whether it exists. Returns ("", false) if the CRD is not installed or
// no CR exists.
func get(dc dynamic.Interface) (string, bool) {
	if dc == nil {
		return "", false
	}
	list, err := dc.Resource(apis.DatastoreMigrationGVR).List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil || len(list.Items) == 0 {
		return "", false
	}
	status, ok := list.Items[0].Object["status"].(map[string]any)
	if !ok {
		return "", true
	}
	phase, _ := status["phase"].(string)
	return phase, true
}

// GetPhase returns the phase of the first DatastoreMigration CR, or empty
// string if none exists or the CRD is not installed.
func GetPhase(dc dynamic.Interface) string {
	phase, _ := get(dc)
	return phase
}

// Exists returns true if at least one DatastoreMigration CR exists.
func Exists(dc dynamic.Interface) bool {
	_, exists := get(dc)
	return exists
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
