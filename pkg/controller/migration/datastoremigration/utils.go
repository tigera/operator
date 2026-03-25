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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/tigera/operator/pkg/ctrlruntime"
)

var log = logf.Log.WithName("datastoremigration")

// DatastoreMigrationGVR is the GroupVersionResource for DatastoreMigration CRs.
var DatastoreMigrationGVR = schema.GroupVersionResource{
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

// get fetches the first DatastoreMigration CR and returns its phase and
// whether it exists. Returns ("", false, nil) if the CRD is not installed or
// no CR exists. Returns a non-nil error for transient failures (API server
// blips, RBAC issues, etc.) so callers can distinguish "no migration" from
// "couldn't check".
func get(dc dynamic.Interface) (string, bool, error) {
	if dc == nil {
		return "", false, nil
	}
	list, err := dc.Resource(DatastoreMigrationGVR).List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		if errors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to list DatastoreMigration CRs: %w", err)
	}
	if len(list.Items) == 0 {
		return "", false, nil
	}
	status, ok := list.Items[0].Object["status"].(map[string]any)
	if !ok {
		return "", true, nil
	}
	phase, _ := status["phase"].(string)
	return phase, true, nil
}

// GetPhase returns the phase of the first DatastoreMigration CR, or empty
// string if none exists or the CRD is not installed. Returns a non-nil error
// for transient failures so callers can decide how to handle uncertainty.
func GetPhase(dc dynamic.Interface) (string, error) {
	phase, _, err := get(dc)
	return phase, err
}

// Exists returns true if at least one DatastoreMigration CR exists. Returns
// a non-nil error for transient failures.
func Exists(dc dynamic.Interface) (bool, error) {
	_, exists, err := get(dc)
	return exists, err
}

// WaitForWatchAndAdd polls for the DatastoreMigration CRD and sets up a watch
// on the given controller once available. This triggers controller reconciliation
// when the migration phase changes. The goroutine exits when ctx is cancelled.
func WaitForWatchAndAdd(ctx context.Context, c ctrlruntime.Controller, cs *kubernetes.Clientset) {
	gvr := DatastoreMigrationGVR
	groupVersion := gvr.Group + "/" + gvr.Version

	duration := 1 * time.Second
	maxDuration := 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			log.Info("Context cancelled, stopping DatastoreMigration watch setup")
			return
		case <-time.After(duration):
		}
		duration = min(2*duration, maxDuration)

		_, err := cs.Discovery().ServerResourcesForGroupVersion(groupVersion)
		if err != nil {
			continue
		}

		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvr.GroupVersion().WithKind("DatastoreMigration"))
		if err := c.WatchObject(obj, &handler.EnqueueRequestForObject{}); err != nil {
			log.V(2).Info("Failed to watch DatastoreMigration, will retry", "error", err)
			continue
		}
		log.Info("Successfully watching DatastoreMigration CRs")
		return
	}
}
