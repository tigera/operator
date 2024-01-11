// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

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

package initializer

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
)

func AddConditionsController(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &LogStorageConditions{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
	}

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-conditions-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-conditions-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-conditions-controller failed to watch Installation resource: %w", err)
	}
	if err = c.Watch(&source.Kind{Type: &operatorv1.TigeraStatus{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-conditions-controller failed to watch TigeraStatus resource: %w", err)
	}

	return nil
}

var _ reconcile.Reconciler = &LogStorageConditions{}

// LogStorageConditions implements a controller that monitors the status of various log storage related TigeraStatus objects and
// updates the LogStorage object's status conditions accordingly.
type LogStorageConditions struct {
	client      client.Client
	scheme      *runtime.Scheme
	multiTenant bool
}

func (r *LogStorageConditions) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage - Conditions")

	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	if err := r.client.Get(ctx, key, ls); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	// Aggregate tiger status for all log storage controllers
	logStorageInstances := []string{TigeraStatusName, TigeraStatusLogStorageAccess, TigeraStatusLogStorageElastic, TigeraStatusLogStorageSecrets, TigeraStatusLogStorageUsers}
	tsLogStorage := &operatorv1.TigeraStatus{}

	available, progressing, degraded := false, false, false
	availableTransitionTime, progressTransitionTime, degTransitionTime := metav1.Time{}, metav1.Time{}, metav1.Time{}
	progressingReason, degReason := operatorv1.Unknown, operatorv1.Unknown
	progressingMsg, degMsg := "", ""

	for _, logStorage := range logStorageInstances {

		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: logStorage}, ts); err != nil {
			return reconcile.Result{}, err
		}

		for _, condition := range ts.Status.Conditions {
			if condition.Type == operatorv1.ComponentAvailable {
				available = true
				if (condition.LastTransitionTime.Time).After(availableTransitionTime.Time) {
					availableTransitionTime = condition.LastTransitionTime
				}
			} else if condition.Type == operatorv1.ComponentProgressing {
				progressing = true
				if (condition.LastTransitionTime.Time).After(progressTransitionTime.Time) {
					progressTransitionTime = condition.LastTransitionTime
				}
				if progressingReason == operatorv1.Unknown {
					progressingReason = operatorv1.TigeraStatusReason(condition.Reason)
				} else {
					progressingReason = operatorv1.ResourceProgressing
				}
				progressingMsg = progressingMsg + condition.Message + ";"
			} else if condition.Type == operatorv1.ComponentDegraded {
				degraded = true
				if (condition.LastTransitionTime.Time).After(degTransitionTime.Time) {
					degTransitionTime = condition.LastTransitionTime
				}

				if degReason == operatorv1.Unknown {
					degReason = operatorv1.TigeraStatusReason(condition.Reason)
				} else {
					progressingReason = operatorv1.ResourceDegraded
				}
				degMsg = degMsg + condition.Message + ";"
			}
		}

	}

	if degraded {
		degradedCondition := operatorv1.TigeraStatusCondition{
			Type:               operatorv1.ComponentDegraded,
			Status:             operatorv1.ConditionTrue,
			LastTransitionTime: degTransitionTime,
			Reason:             string(degReason),
			Message:            degMsg,
		}

		clearAvailable(tsLogStorage.Status.Conditions)
		clearProgressing(tsLogStorage.Status.Conditions)

		tsLogStorage.Status.Conditions = append(tsLogStorage.Status.Conditions, degradedCondition)
		// unset ava,prog
	} else if progressing {
		progressionCondition := operatorv1.TigeraStatusCondition{
			Type:               operatorv1.ComponentProgressing,
			Status:             operatorv1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(progressingReason),
			Message:            progressingMsg,
		}
		// unset prog,deg
		clearAvailable(tsLogStorage.Status.Conditions)
		clearDegraded(tsLogStorage.Status.Conditions)

		tsLogStorage.Status.Conditions = append(tsLogStorage.Status.Conditions, progressionCondition)

	} else if available {
		// Set available
		availableCondition := operatorv1.TigeraStatusCondition{
			Type:               operatorv1.ComponentAvailable,
			Status:             operatorv1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now()),
			Reason:             string(operatorv1.AllObjectsAvailable),
			Message:            "All objects available",
		}

		// unset prog,deg
		clearProgressing(tsLogStorage.Status.Conditions)
		clearDegraded(tsLogStorage.Status.Conditions)

		tsLogStorage.Status.Conditions = append(tsLogStorage.Status.Conditions, availableCondition)
	}

	// End

	ls.Status.Conditions = status.UpdateStatusCondition(ls.Status.Conditions, tsLogStorage.Status.Conditions)
	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.WithValues("reason", err).Info("Failed to update LogStorage status conditions")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func clearProgressing(conditions []operatorv1.TigeraStatusCondition) {
	condition := operatorv1.TigeraStatusCondition{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: ""}
	conditions = append(conditions, condition)
}
func clearAvailable(conditions []operatorv1.TigeraStatusCondition) {
	condition := operatorv1.TigeraStatusCondition{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: ""}
	conditions = append(conditions, condition)
}
func clearDegraded(conditions []operatorv1.TigeraStatusCondition) {
	condition := operatorv1.TigeraStatusCondition{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: ""}
	conditions = append(conditions, condition)
}
