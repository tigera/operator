// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// ExpectResourceCreated asserts that the given object is created,
// and populates the provided runtime.Object with the current state of the object
// in the cluster.
func ExpectResourceCreated(c client.Client, obj runtime.Object) {
	Eventually(func() error {
		return GetResource(c, obj)
	}, 10*time.Second).Should(BeNil())
}

// GetResource gets the requested object, populating obj with its contents.
func GetResource(c client.Client, obj runtime.Object) error {
	k := client.ObjectKey{
		Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
		Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
	}
	return c.Get(context.Background(), k, obj)
}

// RunOperator runs the provided operator manager in a separate goroutine so that
// the test code isn't blocked. It returns a stop channel which can be closed in order to
// stop the execution of the operator.
func RunOperator(mgr manager.Manager) chan struct{} {
	stopChan := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		err := mgr.Start(stopChan)
		Expect(err).NotTo(HaveOccurred())
	}()
	return stopChan
}
