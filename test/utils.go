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

package test

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

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

// ExpectResourceDestroyed asserts that the given object no longer exists.
func ExpectResourceDestroyed(c client.Client, obj runtime.Object) {
	var err error
	Eventually(func() error {
		err = GetResource(c, obj)
		return err
	}, 10*time.Second).ShouldNot(BeNil())

	serr, ok := err.(*errors.StatusError)
	Expect(ok).To(BeTrue(), fmt.Sprintf("error was not StatusError: %v", err))
	Expect(serr.ErrStatus.Code).To(Equal(int32(404)))
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
// the test code isn't blocked. The passed in stop channel can be closed in order to
// stop the execution of the operator.
// The channel returned will be closed when the mgr stops.
func RunOperator(mgr manager.Manager, stopChan chan struct{}) (doneChan chan struct{}) {
	doneChan = make(chan struct{})
	go func() {
		defer GinkgoRecover()
		_ = mgr.Start(stopChan)
		close(doneChan)
		// This should not error but it does. Something is not stopping or closing down but
		// this does not cause other errors. This started happening after updating to
		// operator-sdk v1.0.1 from v0.10.0.
		//Expect(err).NotTo(HaveOccurred(), func() string {
		//	var buf bytes.Buffer
		//	pprof.Lookup("goroutine").WriteTo(&buf, 2)
		//	return buf.String()
		//})
	}()
	synced := mgr.GetCache().WaitForCacheSync(stopChan)
	Expect(synced).To(BeTrue(), "manager cache failed to sync")
	return doneChan
}
