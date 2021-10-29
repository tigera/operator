// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// GetWindowsNodes returns Windows nodes, optionally filtering the list of nodes
// with the given filter functions.
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type ObjPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// AddNodeLabel adds the specified label to the named node. Perform
// Get/Check/Update so that it always working on latest version.
// If node labels has been set already, do nothing.
func AddNodeLabel(ctx context.Context, client kubernetes.Interface, nodeName, key, value string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := true
		if curr, ok := node.Labels[key]; ok && curr == value {
			needUpdate = false
		}

		k := strings.Replace(key, "/", "~1", -1)

		lp := []ObjPatch{{
			Op:    "add",
			Path:  fmt.Sprintf("/metadata/labels/%s", k),
			Value: value,
		}}

		if needUpdate {
			err = PatchNode(ctx, client, nodeName, lp...)
			if err == nil {
				return true, nil
			}
			if !apierrors.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

func PatchNode(ctx context.Context, client kubernetes.Interface, nodeName string, jsonStringPatches ...ObjPatch) error {
	patchBytes, err := json.Marshal(jsonStringPatches)
	if err != nil {
		return err
	}

	_, err = client.CoreV1().Nodes().Patch(ctx, nodeName, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
	return err
}

// RemoveNodeLabel removes the specified label from the named node. Perform Get/Check/Update so that it always working on the
// most recent version of the resource.
// If node labels do not exist, do nothing.
func RemoveNodeLabel(ctx context.Context, client kubernetes.Interface, nodeName, key string) error {
	return wait.PollImmediate(1*time.Second, 1*time.Minute, func() (bool, error) {
		node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		if _, ok := node.Labels[key]; ok {
			needUpdate = true
		}

		// With JSONPatch '/' must be escaped as '~1' http://jsonpatch.com/
		k := strings.Replace(key, "/", "~1", -1)
		lp := []ObjPatch{{
			Op:   "remove",
			Path: fmt.Sprintf("/metadata/labels/%s", k),
		}}

		if needUpdate {
			err = PatchNode(ctx, client, nodeName, lp...)
			if err == nil {
				return true, nil
			}
			if !apierrors.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// CreateNodeSharedIndexInformer returns a Node shared index informer used
// by the typhaAutoscaler and the calicoWindowsUpgrader.
func CreateNodeSharedIndexInformer(nodeListWatch cache.ListerWatcher) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(nodeListWatch, &corev1.Node{}, 0, cache.Indexers{})
}
