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
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	// Log storage instances to fetch TigeraStatus
	logStorageInstances := []string{TigeraStatusName, TigeraStatusLogStorageAccess, TigeraStatusLogStorageElastic, TigeraStatusLogStorageSecrets}

	// log-storage user exist only in multitenant enviroment
	if r.multiTenant {
		logStorageInstances = append(logStorageInstances, TigeraStatusLogStorageUsers)
	}

	// Initialize aggregated TigeraStatus conditions with default values
	aggTigeraStatusConditions := []operatorv1.TigeraStatusCondition{
		{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
		{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
		{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown), Message: "", LastTransitionTime: metav1.Time{}},
	}

	// Map to keep track of the conditions status for each type.
	statusMap := make(map[operatorv1.StatusConditionType]bool)

	for _, logStorage := range logStorageInstances {
		// Fetch TigeraStatus for the individual log storage subcontrollers.
		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: logStorage}, ts); err != nil && apierrors.IsNotFound(err) {

			// When one of the expected subcontroller is not found, update it as degraded
			ts.Status = operatorv1.TigeraStatusStatus{
				Conditions: []operatorv1.TigeraStatusCondition{
					{Type: operatorv1.ComponentDegraded,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.ResourceNotFound),
						Message:            "",
						LastTransitionTime: metav1.Now()},
				}}

		} else if err != nil {
			return reconcile.Result{}, err
		}

		// Update aggregated conditions based on fetched TigeraStatus
		updateAggregatedConditions(ts.Status.Conditions, aggTigeraStatusConditions, statusMap, logStorage)
	}

	// Update tigera status conditions based on statusMap
	if statusMap[operatorv1.ComponentDegraded] {
		degradedMessage := fmt.Sprintf("The following sub-controllers are degraded")
		setAndClearTigeraStatus(aggTigeraStatusConditions, operatorv1.ComponentDegraded, []operatorv1.StatusConditionType{operatorv1.ComponentAvailable}, string(operatorv1.ResourceNotReady), degradedMessage)
	}
	if statusMap[operatorv1.ComponentProgressing] {
		progMessage := fmt.Sprintf("The following sub-controllers are progresssing")
		setAndClearTigeraStatus(aggTigeraStatusConditions, operatorv1.ComponentProgressing, []operatorv1.StatusConditionType{operatorv1.ComponentAvailable}, string(operatorv1.ResourceNotReady), progMessage)
	}
	if statusMap[operatorv1.ComponentAvailable] && !statusMap[operatorv1.ComponentDegraded] && !statusMap[operatorv1.ComponentProgressing] {
		setAndClearTigeraStatus(aggTigeraStatusConditions, operatorv1.ComponentAvailable, []operatorv1.StatusConditionType{operatorv1.ComponentProgressing, operatorv1.ComponentDegraded}, string(operatorv1.AllObjectsAvailable), "All Objects are available")
	}

	// Resets TransitionTime to previously computed condition when condition status remain unchanged
	resetLastTransitionTimeStamp(aggTigeraStatusConditions, ls.Status.Conditions)

	ls.Status.Conditions = status.UpdateStatusCondition(ls.Status.Conditions, aggTigeraStatusConditions)
	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.WithValues("reason", err).Info("Failed to update LogStorage status conditions")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// resetLastTransitionTimeStamp sets the LastTransitionTime to the previously computed condition
// when the condition status remains unchanged
func resetLastTransitionTimeStamp(aggTigeraStatusConditions []operatorv1.TigeraStatusCondition, ls []metav1.Condition) {

	for i := range aggTigeraStatusConditions {
		for _, lsCondition := range ls {
			if aggTigeraStatusConditions[i].Type == operatorv1.ComponentAvailable && lsCondition.Type == string(operatorv1.ComponentReady) ||
				aggTigeraStatusConditions[i].Type == operatorv1.ComponentDegraded && lsCondition.Type == string(operatorv1.ComponentDegraded) ||
				aggTigeraStatusConditions[i].Type == operatorv1.ComponentProgressing && lsCondition.Type == string(operatorv1.ComponentProgressing) {
				// Retain the old LastTransitionTime when the condition type's status is unchanged.
				// TODO remove comment - Compare the messages in case when progressing or degraded is still true with one or more component flicker between degraded and progressing.
				if string(aggTigeraStatusConditions[i].Status) == string(lsCondition.Status) && aggTigeraStatusConditions[i].Message == lsCondition.Message {
					aggTigeraStatusConditions[i].LastTransitionTime = lsCondition.LastTransitionTime
				}
			}
		}
	}
}

func setAndClearTigeraStatus(aggTigeraStatusConditions []operatorv1.TigeraStatusCondition, conditionType operatorv1.StatusConditionType, clearTypes []operatorv1.StatusConditionType, reason, message string) {

	for i := range aggTigeraStatusConditions {
		if aggTigeraStatusConditions[i].Type == conditionType {
			aggTigeraStatusConditions[i].Status = operatorv1.ConditionTrue
			aggTigeraStatusConditions[i].Message = fmt.Sprintf("%s:%s", message, strings.TrimSuffix(aggTigeraStatusConditions[i].Message, ","))
		} else {
			for _, clearType := range clearTypes {
				if aggTigeraStatusConditions[i].Type == clearType {
					aggTigeraStatusConditions[i].Status = operatorv1.ConditionFalse
					aggTigeraStatusConditions[i].Message = ""
				}
			}
		}
		aggTigeraStatusConditions[i].Reason = reason
		if conditionType == operatorv1.ComponentAvailable {
			aggTigeraStatusConditions[i].Message = message
		}
	}
}

func updateAggregatedConditions(tsConditions []operatorv1.TigeraStatusCondition, aggTigeraStatusConditions []operatorv1.TigeraStatusCondition, statusMap map[operatorv1.StatusConditionType]bool, logStorageType string) {
	for _, condition := range tsConditions {
		for i := range aggTigeraStatusConditions {
			if aggTigeraStatusConditions[i].Type == condition.Type {

				statusMap[condition.Type] = statusMap[condition.Type] || (condition.Status == operatorv1.ConditionTrue)
				// Available should be marked true when all of the subcontrollers are available.
				if aggTigeraStatusConditions[i].Type == operatorv1.ComponentAvailable {
					statusMap[condition.Type] = statusMap[condition.Type] && (condition.Status == operatorv1.ConditionTrue)
				}

				// Aggregate component name to construct message when condition is true
				if condition.Status == operatorv1.ConditionTrue {
					aggTigeraStatusConditions[i].Message = fmt.Sprintf("%s%s,", aggTigeraStatusConditions[i].Message, logStorageType)
				}

				// Update the most recent transition time
				if aggTigeraStatusConditions[i].LastTransitionTime.Time.Before(condition.LastTransitionTime.Time) {
					aggTigeraStatusConditions[i].LastTransitionTime = condition.LastTransitionTime
				}

				// Set the oldest Observed Generation
				if condition.ObservedGeneration != 0 && (aggTigeraStatusConditions[i].ObservedGeneration == 0 || condition.ObservedGeneration < aggTigeraStatusConditions[i].ObservedGeneration) {
					aggTigeraStatusConditions[i].ObservedGeneration = condition.ObservedGeneration
				}
			}
		}
	}
}
