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

	//Initialize aggregated TigeraStatus conditions with default values.
	tsAggConditions := []operatorv1.TigeraStatusCondition{
		{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
		{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
		{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
	}

	// Map to keep track of the status conditions for each type.
	statusMap := make(map[operatorv1.StatusConditionType]bool)

	// Loop through all log storage instances.
	for _, logStorage := range logStorageInstances {

		// Fetch TigeraStatus for the individual log storage subcontrollers.
		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: logStorage}, ts); err != nil {
			return reconcile.Result{}, err
		}

		for _, condition := range ts.Status.Conditions {
			for i := range tsAggConditions {
				if tsAggConditions[i].Type == condition.Type {
					tsAggConditions[i].Status = condition.Status
					tsAggConditions[i].Message = fmt.Sprintf("%s%s for %s;", tsAggConditions[i].Message, condition.Message, logStorage)
					if tsAggConditions[i].LastTransitionTime.Time.Before(condition.LastTransitionTime.Time) {
						tsAggConditions[i].LastTransitionTime = condition.LastTransitionTime
					}
					statusMap[condition.Type] = statusMap[condition.Type] || (condition.Status == operatorv1.ConditionTrue)
				}
			}
		}
	}

	if statusMap[operatorv1.ComponentDegraded] {
		setTigeraStatus(tsAggConditions, operatorv1.ComponentDegraded, string(operatorv1.ResourceDegraded))
		clearTigeraStatus(tsAggConditions, []operatorv1.StatusConditionType{operatorv1.ComponentAvailable, operatorv1.ComponentProgressing}, string(operatorv1.ResourceDegraded))
	} else if statusMap[operatorv1.ComponentProgressing] {
		setTigeraStatus(tsAggConditions, operatorv1.ComponentProgressing, string(operatorv1.ResourceProgressing))
		clearTigeraStatus(tsAggConditions, []operatorv1.StatusConditionType{operatorv1.ComponentAvailable, operatorv1.ComponentDegraded}, string(operatorv1.ResourceProgressing))
	} else if statusMap[operatorv1.ComponentAvailable] {
		setTigeraStatus(tsAggConditions, operatorv1.ComponentAvailable, string(operatorv1.AllObjectsAvailable))
		clearTigeraStatus(tsAggConditions, []operatorv1.StatusConditionType{operatorv1.ComponentProgressing, operatorv1.ComponentDegraded}, string(operatorv1.AllObjectsAvailable))
	}

	ls.Status.Conditions = status.UpdateStatusCondition(ls.Status.Conditions, tsAggConditions)
	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.WithValues("reason", err).Info("Failed to update LogStorage status conditions")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func setTigeraStatus(tsAggConditions []operatorv1.TigeraStatusCondition, conditionType operatorv1.StatusConditionType, reason string) {
	for i := range tsAggConditions {
		if tsAggConditions[i].Type == conditionType {
			tsAggConditions[i].Status = operatorv1.ConditionTrue
			tsAggConditions[i].Reason = reason
		}
	}
}

func clearTigeraStatus(tsAggConditions []operatorv1.TigeraStatusCondition, conditionTypes []operatorv1.StatusConditionType, reason string) {
	for i := range tsAggConditions {
		for _, conditionType := range conditionTypes {
			if tsAggConditions[i].Type == conditionType {
				tsAggConditions[i].Status = operatorv1.ConditionFalse
				tsAggConditions[i].Reason = reason
				tsAggConditions[i].Message = ""
			}
		}
	}
}
