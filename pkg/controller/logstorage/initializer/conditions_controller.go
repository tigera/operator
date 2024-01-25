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
	"time"

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

	// Fetch the current status condition for log storage
	currentCondition := getCurrentConditions(ls.Status.Conditions)

	// Aggregate TigeraStatus conditions from all logstorage subcontrollers into a map,
	// using the condition type (e.g., Available, Progressing, and Degraded) as the key.
	desiredConditions, err := r.getDesiredConditions(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Compare and update the current StatusCondition if there are any new changes
	ls.Status.Conditions = updateConditions(currentCondition, desiredConditions)

	if err := r.client.Status().Update(ctx, ls); err != nil {
		log.WithValues("reason", err).Info("Failed to update LogStorage status conditions")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func getCurrentConditions(lsConditions []metav1.Condition) map[string]metav1.Condition {
	statusCondition := make(map[string]metav1.Condition)
	for _, condition := range lsConditions {
		statusCondition[condition.Type] = condition
	}
	return statusCondition
}

// getDesiredConditions checks sub-controller TigeraStatus objects and builds the desired
// conditions based on the health of each. It returns a map for easy lookup - the key is the condition type.
func (r *LogStorageConditions) getDesiredConditions(ctx context.Context) (map[string]metav1.Condition, error) {

	desiredTigeraStatusMap := make(map[operatorv1.StatusConditionType]operatorv1.TigeraStatusCondition)

	logStorageInstances := []string{TigeraStatusName, TigeraStatusLogStorageAccess, TigeraStatusLogStorageElastic, TigeraStatusLogStorageSecrets}
	if r.multiTenant {
		logStorageInstances = append(logStorageInstances, TigeraStatusLogStorageUsers)
	} else {
		logStorageInstances = append(logStorageInstances, TigeraStatusLogStorageESMetrics, TigeraStatusLogStorageKubeController)
	}

	for _, logStorage := range logStorageInstances {

		// Fetch TigeraStatus for the individual log storage subcontrollers.
		ts := &operatorv1.TigeraStatus{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: logStorage}, ts); err != nil && errors.IsNotFound(err) {
			// When one of the expected subcontroller is not found, update it as degraded
			ts.Status = operatorv1.TigeraStatusStatus{
				Conditions: []operatorv1.TigeraStatusCondition{
					{
						Type:               operatorv1.ComponentDegraded,
						Status:             operatorv1.ConditionTrue,
						Reason:             string(operatorv1.ResourceNotFound),
						Message:            "",
						LastTransitionTime: metav1.Now(),
					},
				},
			}
		} else if err != nil {
			return nil, err
		}

		// Merge TigeraStatus conditions from subcontrollers into a map.
		for _, tsCondition := range ts.Status.Conditions {
			if desiredCondition, ok := desiredTigeraStatusMap[tsCondition.Type]; ok {
				desiredTigeraStatusMap[tsCondition.Type] = mergeCondition(tsCondition, desiredCondition, logStorage)
			} else {
				desiredTigeraStatusMap[tsCondition.Type] = tsCondition
			}
		}
	}

	return transformIntoLogStorageConditions(desiredTigeraStatusMap), nil
}

// Transform TigeraStatus conditions of type TigeraStatusCondition into metav1.Conditions
// to compare with the current logStorage conditions.
func transformIntoLogStorageConditions(desiredConditions map[operatorv1.StatusConditionType]operatorv1.TigeraStatusCondition) map[string]metav1.Condition {

	desiredLogStorageCondition := make(map[string]metav1.Condition)

	// if Degraded or Progressing is true, then Available should be marked as false even
	// if tigerastatus have both Available and Degraded/Progressing set to True.
	isDegOrProg := false

	// Check for Degraded
	if degradedCondition, ok := desiredConditions[operatorv1.ComponentDegraded]; ok {
		observedGeneration := degradedCondition.ObservedGeneration
		if degradedCondition.Status == operatorv1.ConditionTrue {
			isDegOrProg = true
			desiredLogStorageCondition[string(operatorv1.ComponentDegraded)] = setDegraded(degradedCondition)
			desiredLogStorageCondition[string(operatorv1.ComponentReady)] = clearAvailable(observedGeneration)
		} else {
			desiredLogStorageCondition[string(operatorv1.ComponentDegraded)] = clearDegraded(string(operatorv1.Unknown), "", observedGeneration)
		}
	}

	// Check for Progressing
	if progressingCondition, ok := desiredConditions[operatorv1.ComponentProgressing]; ok {
		observedGeneration := progressingCondition.ObservedGeneration
		if progressingCondition.Status == operatorv1.ConditionTrue {
			isDegOrProg = true
			desiredLogStorageCondition[string(operatorv1.ComponentProgressing)] = setProgressing(progressingCondition)
			desiredLogStorageCondition[string(operatorv1.ComponentReady)] = clearAvailable(observedGeneration)
		} else {
			reason := string(operatorv1.Unknown)
			// if degraded and no progressing components set reason as ResourceNotReady
			if isDegOrProg {
				reason = string(operatorv1.ResourceNotReady)
			}
			desiredLogStorageCondition[string(operatorv1.ComponentProgressing)] = clearProgressing(reason, "", observedGeneration)
		}
	}

	// Check for Available
	if availableCondition, ok := desiredConditions[operatorv1.ComponentAvailable]; ok && !isDegOrProg {
		// Set Available as true and clear degraded and progressing
		observedGeneration := availableCondition.ObservedGeneration
		if availableCondition.Status == operatorv1.ConditionTrue {
			desiredLogStorageCondition[string(operatorv1.ComponentReady)] = setAvailable(availableCondition)
			desiredLogStorageCondition[string(operatorv1.ComponentProgressing)] = clearProgressing(string(operatorv1.AllObjectsAvailable), "All objects are available", observedGeneration)
			desiredLogStorageCondition[string(operatorv1.ComponentDegraded)] = clearDegraded(string(operatorv1.AllObjectsAvailable), "All objects are available", observedGeneration)
		} else {
			desiredLogStorageCondition[string(operatorv1.ComponentReady)] = clearAvailable(observedGeneration)
		}
	}

	return desiredLogStorageCondition
}

func updateConditions(currentConditions, desiredConditions map[string]metav1.Condition) []metav1.Condition {

	statusCondition := []metav1.Condition{}

	//Update the current log storage condition only when the aggregate desired status have new changes
	for _, desired := range desiredConditions {
		found := false
		var condition metav1.Condition
		for _, current := range currentConditions {
			if desired.Type == string(operatorv1.ComponentAvailable) && current.Type == string(operatorv1.ComponentReady) ||
				desired.Type == string(operatorv1.ComponentDegraded) && current.Type == string(operatorv1.ComponentDegraded) ||
				desired.Type == string(operatorv1.ComponentProgressing) && current.Type == string(operatorv1.ComponentProgressing) {
				//Defaults to current log storage condition
				condition = current
				if string(desired.Status) != string(current.Status) || desired.Message != current.Message {
					// if status or the message is updated then use the desired condition
					condition = desired
					condition.LastTransitionTime = metav1.NewTime(time.Now())
				}
				found = true
			}
		}
		// if the desired condition is not found in the current logstorage condition then add it.
		if !found {
			condition = desired
			condition.LastTransitionTime = metav1.NewTime(time.Now())
		}

		statusCondition = append(statusCondition, condition)
	}
	return statusCondition
}

func setAvailable(desired operatorv1.TigeraStatusCondition) metav1.Condition {
	return metav1.Condition{
		Type:               string(operatorv1.ComponentReady),
		Status:             metav1.ConditionTrue,
		Message:            "All Objects are available",
		Reason:             string(operatorv1.AllObjectsAvailable),
		ObservedGeneration: desired.ObservedGeneration,
	}
}

func setProgressing(desired operatorv1.TigeraStatusCondition) metav1.Condition {
	message := fmt.Sprintf("The following sub-controllers are progressing:%s", strings.TrimSuffix(desired.Message, ","))
	return metav1.Condition{
		Type:               string(operatorv1.ComponentProgressing),
		Status:             metav1.ConditionTrue,
		Message:            message,
		Reason:             string(operatorv1.ResourceNotReady),
		ObservedGeneration: desired.ObservedGeneration,
	}
}

func setDegraded(desired operatorv1.TigeraStatusCondition) metav1.Condition {
	degradedMessage := fmt.Sprintf("The following sub-controllers are degraded:%s", strings.TrimSuffix(desired.Message, ","))
	return metav1.Condition{
		Type:               string(operatorv1.ComponentDegraded),
		Status:             metav1.ConditionTrue,
		Message:            degradedMessage,
		Reason:             string(operatorv1.ResourceNotReady),
		ObservedGeneration: desired.ObservedGeneration,
	}
}

func clearAvailable(generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               operatorv1.TigeraStatusReady,
		Status:             metav1.ConditionFalse,
		Message:            "",
		Reason:             string(operatorv1.ResourceNotReady),
		ObservedGeneration: generation,
	}
}

func clearProgressing(reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(operatorv1.ComponentProgressing),
		Status:             metav1.ConditionFalse,
		Message:            message,
		Reason:             reason,
		ObservedGeneration: generation,
	}
}

func clearDegraded(reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(operatorv1.ComponentDegraded),
		Status:             metav1.ConditionFalse,
		Message:            message,
		Reason:             reason,
		ObservedGeneration: generation,
	}
}

func mergeCondition(tsCondition operatorv1.TigeraStatusCondition, desiredCondition operatorv1.TigeraStatusCondition, logStorageName string) operatorv1.TigeraStatusCondition {
	if tsCondition.Type == operatorv1.ComponentAvailable {
		return mergeAvailableCondition(tsCondition, desiredCondition)
	}
	return mergeProgressingORDegradedCondition(tsCondition, desiredCondition, logStorageName)

}

func mergeAvailableCondition(tsCondition operatorv1.TigeraStatusCondition, desiredCondition operatorv1.TigeraStatusCondition) operatorv1.TigeraStatusCondition {
	tmpCondition := operatorv1.TigeraStatusCondition{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown)}
	if tsCondition.Status == operatorv1.ConditionTrue && desiredCondition.Status == operatorv1.ConditionTrue {
		tmpCondition.Status = operatorv1.ConditionTrue
	}

	if tsCondition.Status == operatorv1.ConditionFalse {
		tmpCondition.Reason = string(operatorv1.ResourceNotReady)
	}

	// Set the oldest Observed Generation
	if tsCondition.ObservedGeneration != 0 && (desiredCondition.ObservedGeneration == 0 || tsCondition.ObservedGeneration < desiredCondition.ObservedGeneration) {
		tmpCondition.ObservedGeneration = tsCondition.ObservedGeneration
	}

	return tmpCondition
}

func mergeProgressingORDegradedCondition(tsCondition operatorv1.TigeraStatusCondition, desiredCondition operatorv1.TigeraStatusCondition, logStorageName string) operatorv1.TigeraStatusCondition {
	tmpCondition := operatorv1.TigeraStatusCondition{Type: tsCondition.Type, Status: operatorv1.ConditionFalse, Reason: string(operatorv1.Unknown)}
	if tsCondition.Status == operatorv1.ConditionTrue || desiredCondition.Status == operatorv1.ConditionTrue {
		tmpCondition.Status = operatorv1.ConditionTrue
	}

	if tsCondition.Status == operatorv1.ConditionTrue {
		tmpCondition.Message = fmt.Sprintf("%s%s,", desiredCondition.Message, logStorageName)
		tmpCondition.Reason = string(operatorv1.ResourceNotReady)
	}

	// Set the oldest Observed Generation
	if tsCondition.ObservedGeneration != 0 && (desiredCondition.ObservedGeneration == 0 || tsCondition.ObservedGeneration < desiredCondition.ObservedGeneration) {
		tmpCondition.ObservedGeneration = tsCondition.ObservedGeneration
	}
	return tmpCondition
}
