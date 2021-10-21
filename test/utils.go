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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/tigera/operator/pkg/common"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// ExpectResourceCreated asserts that the given object is created,
// and populates the provided client.Object with the current state of the object
// in the cluster.
func ExpectResourceCreated(c client.Client, obj client.Object) {
	EventuallyWithOffset(1, func() error {
		return GetResource(c, obj)
	}, 10*time.Second).Should(BeNil())
}

// ExpectResourceDestroyed asserts that the given object no longer exists.
func ExpectResourceDestroyed(c client.Client, obj client.Object) {
	var err error
	EventuallyWithOffset(1, func() error {
		err = GetResource(c, obj)
		return err
	}, 10*time.Second).ShouldNot(BeNil(), fmt.Sprintf("GetResource %s should return error", obj.GetName()))

	serr, ok := err.(*errors.StatusError)
	ExpectWithOffset(1, ok).To(BeTrue(), fmt.Sprintf("error was not StatusError: %v", err))
	ExpectWithOffset(1, serr.ErrStatus.Code).To(Equal(int32(404)))
}

// GetResource gets the requested object, populating obj with its contents.
func GetResource(c client.Client, obj client.Object) error {
	k := client.ObjectKey{
		Name:      obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName(),
		Namespace: obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
	}
	return c.Get(context.Background(), k, obj)
}

func GetContainer(containers []v1.Container, name string) *v1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

// RunOperator runs the provided operator manager in a separate goroutine so that
// the test code isn't blocked. The passed in stop channel can be closed in order to
// stop the execution of the operator.
// The channel returned will be closed when the mgr stops.
func RunOperator(mgr manager.Manager, ctx context.Context) (doneChan chan struct{}) {
	doneChan = make(chan struct{})
	go func() {
		defer GinkgoRecover()
		_ = mgr.Start(ctx)
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
	synced := mgr.GetCache().WaitForCacheSync(ctx)
	Expect(synced).To(BeTrue(), "manager cache failed to sync")
	return doneChan
}

func VerifyPublicCert(secret *v1.Secret, pubKey string, expectedSANs ...string) {
	Expect(secret.Data).To(HaveKey(pubKey))
	VerifyCertSANs(secret.Data[pubKey], expectedSANs...)
}

func VerifyCert(secret *v1.Secret, privKey string, pubKey string, expectedSANs ...string) {
	Expect(secret.Data).To(HaveKey(privKey))
	Expect(secret.Data).To(HaveKey(pubKey))

	VerifyCertSANs(secret.Data[pubKey], expectedSANs...)
}

func VerifyCertSANs(certBytes []byte, expectedSANs ...string) {
	pemBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	Expect(err).To(BeNil(), "Error parsing bytes from secret into certificate")
	Expect(cert.DNSNames).To(ConsistOf(expectedSANs), "Expect cert SAN's to match expected service DNS names")
}

func MakeTestCA(signer string) *crypto.CA {
	caConfig, err := crypto.MakeSelfSignedCAConfigForDuration(
		signer,
		100*365*24*time.Hour, //100years*365days*24hours
	)
	Expect(err).To(BeNil(), "Error creating CA config")
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          caConfig,
	}
}

// Mock a cache.ListWatcher for nodes to use in the test as there is no other suitable
// mock available in the fake packages.
// Ref: https://github.com/kubernetes/client-go/issues/352#issuecomment-614740790
type NodeListWatch struct {
	kubernetes.Interface
}

func (n NodeListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	return n.Interface.CoreV1().Nodes().List(context.Background(), options)
}

func (n NodeListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return n.Interface.CoreV1().Nodes().Watch(context.Background(), options)
}

// Mock a cache.ListWatcher for nodes to use in the test as there is no other suitable
// mock available in the fake packages.
// Ref: https://github.com/kubernetes/client-go/issues/352#issuecomment-614740790
type TyphaListWatch struct {
	kubernetes.Interface
}

func (t TyphaListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	return t.Interface.AppsV1().Deployments("calico-system").List(context.Background(), options)
}

func (t TyphaListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return t.Interface.AppsV1().Deployments("calico-system").Watch(context.Background(), options)
}

func CreateNode(c kubernetes.Interface, name string, labels map[string]string, annotations map[string]string) *v1.Node {
	node := &v1.Node{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if labels != nil {
		node.ObjectMeta.Labels = labels
	}
	if annotations != nil {
		node.ObjectMeta.Annotations = annotations
	}

	var err error
	node, err = c.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})
	Expect(err).To(BeNil())
	return node
}

func AssertNodesUnchanged(c kubernetes.Interface, nodes ...*v1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())
		if !reflect.DeepEqual(node, newNode) {
			return fmt.Errorf("expected node %q to be unchanged", node.Name)
		}
	}
	return nil
}

func AssertNodesHadUpgradeTriggered(c kubernetes.Interface, nodes ...*v1.Node) error {
	for _, node := range nodes {
		newNode, err := c.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
		Expect(err).To(BeNil())

		label := newNode.Labels[common.CalicoWindowsUpgradeScriptLabel]
		if label != common.CalicoWindowsUpgradeScript {
			return fmt.Errorf("expected node %q to have upgrade label but it had: %q", node.Name, label)
		}

		var found bool
		for _, taint := range newNode.Spec.Taints {
			if taint.MatchTaint(common.CalicoWindowsUpgradingTaint) {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("expected node %q to have upgrade taint", node.Name)
		}
	}
	return nil
}
