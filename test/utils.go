// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

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
	"strings"
	"time"

	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/openshift/library-go/pkg/crypto"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/status"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
func ExpectResourceDestroyed(c client.Client, obj client.Object, timeout time.Duration) {
	var err error
	EventuallyWithOffset(1, func() error {
		err = GetResource(c, obj)
		if errors.IsNotFound(err) || errors.IsGone(err) {
			return nil
		} else if err != nil {
			return err
		} else {
			return fmt.Errorf("%T '%s' should no longer exist", obj, obj.GetName())
		}
	}, timeout).ShouldNot(HaveOccurred())

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

func VerifyCert(secret *v1.Secret, expectedSANs ...string) {
	Expect(secret.Data).To(HaveKey(corev1.TLSPrivateKeyKey))
	Expect(secret.Data).To(HaveKey(corev1.TLSCertKey))

	VerifyCertSANs(secret.Data[corev1.TLSCertKey], expectedSANs...)
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
		100*365*24*time.Hour, // 100years*365days*24hours
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
type nodeListWatch struct {
	cs kubernetes.Interface
}

func NewNodeListWatch(cs kubernetes.Interface) nodeListWatch {
	return nodeListWatch{cs: cs}
}

func (n nodeListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	return n.cs.CoreV1().Nodes().List(context.Background(), options)
}

func (n nodeListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return n.cs.CoreV1().Nodes().Watch(context.Background(), options)
}

// Mock a cache.ListWatcher for nodes to use in the test as there is no other suitable
// mock available in the fake packages.
// Ref: https://github.com/kubernetes/client-go/issues/352#issuecomment-614740790
type typhaListWatch struct {
	cs kubernetes.Interface
}

func NewTyphaListWatch(cs kubernetes.Interface) typhaListWatch {
	return typhaListWatch{cs: cs}
}

func (t typhaListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	return t.cs.AppsV1().Deployments("calico-system").List(context.Background(), options)
}

func (t typhaListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return t.cs.AppsV1().Deployments("calico-system").Watch(context.Background(), options)
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

func CreateWindowsNode(cs kubernetes.Interface, name string, variant operator.ProductVariant, version string) *v1.Node {
	return CreateNode(cs, name,
		map[string]string{"kubernetes.io/os": "windows"},
		map[string]string{})
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

// DeleteAllowTigeraTierAndExpectWait deletes the tier resource and expects the Reconciler issues a degraded status, waiting for
// the tier to become available before progressing its status further. Assumes that mockStatus has any required initial status
// progression expectations set, and that the Reconciler utilizes the mockStatus object. Assumes the tier resource has been created.
func DeleteAllowTigeraTierAndExpectWait(ctx context.Context, c client.Client, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	err := c.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"}})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.On("SetDegraded", operator.ResourceNotReady, "Waiting for allow-tigera tier to be created, see the 'tiers' TigeraStatus for more information", "tiers.projectcalico.org \"allow-tigera\" not found", mock.Anything).Return()
	_, err = r.Reconcile(ctx, reconcile.Request{})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.AssertExpectations(GinkgoT())
}

// ExpectWaitForTierWatch expects the Reconciler issues a degraded status, waiting for a Tier watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForTierWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus) {
	ExpectWaitForWatch(ctx, r, mockStatus, "Waiting for Tier watch to be established")
}

// ExpectWaitForWatch expects the Reconciler issues a degraded status, waiting for a watch to be established.
// Assumes that mockStatus has any required initial status progression expectations set, and that the Reconciler utilizes
// the mockStatus object.
func ExpectWaitForWatch(ctx context.Context, r reconcile.Reconciler, mockStatus *status.MockStatus, message string) {
	mockStatus.On("SetDegraded", operator.ResourceNotReady, message, mock.Anything, mock.Anything).Return()
	_, err := r.Reconcile(ctx, reconcile.Request{})
	Expect(err).ShouldNot(HaveOccurred())
	mockStatus.AssertExpectations(GinkgoT())
}

type ObjectTrackerCall string

const (
	ObjectTrackerCallGet    ObjectTrackerCall = "get"
	ObjectTrackerCallCreate ObjectTrackerCall = "create"
	ObjectTrackerCallUpdate ObjectTrackerCall = "update"
	ObjectTrackerCallList   ObjectTrackerCall = "list"
	ObjectTrackerCallDelete ObjectTrackerCall = "delete"
	ObjectTrackerCallWatch  ObjectTrackerCall = "watch"
)

func NewObjectTrackerWithCalls(clientScheme testing.ObjectScheme) ObjectTrackerWithCalls {
	return ObjectTrackerWithCalls{
		ObjectTracker: testing.NewObjectTracker(clientScheme, scheme.Codecs.UniversalDecoder()),
		callsByGVR:    make(map[schema.GroupVersionResource]map[ObjectTrackerCall]int),
	}
}

// ObjectTrackerWithCalls wraps the default implementation of testing.ObjectTracker to track the calls made.
type ObjectTrackerWithCalls struct {
	testing.ObjectTracker
	callsByGVR map[schema.GroupVersionResource]map[ObjectTrackerCall]int
}

func (o *ObjectTrackerWithCalls) Add(obj runtime.Object) error {
	return o.ObjectTracker.Add(obj)
}

func (o *ObjectTrackerWithCalls) inc(gvr schema.GroupVersionResource, call ObjectTrackerCall) {
	if o.callsByGVR == nil {
		o.callsByGVR = make(map[schema.GroupVersionResource]map[ObjectTrackerCall]int)
	}

	if o.callsByGVR[gvr] == nil {
		o.callsByGVR[gvr] = make(map[ObjectTrackerCall]int)
	}

	o.callsByGVR[gvr][call]++
}

func (o *ObjectTrackerWithCalls) CallCount(gvr schema.GroupVersionResource, call ObjectTrackerCall) int {
	return o.callsByGVR[gvr][call]
}

func (o *ObjectTrackerWithCalls) Get(gvr schema.GroupVersionResource, ns, name string, _ ...metav1.GetOptions) (runtime.Object, error) {
	o.inc(gvr, ObjectTrackerCallGet)
	return o.ObjectTracker.Get(gvr, ns, name)
}

func (o *ObjectTrackerWithCalls) Create(gvr schema.GroupVersionResource, obj runtime.Object, ns string, _ ...metav1.CreateOptions) error {
	o.inc(gvr, ObjectTrackerCallCreate)
	return o.ObjectTracker.Create(gvr, obj, ns)
}

func (o *ObjectTrackerWithCalls) Update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, _ ...metav1.UpdateOptions) error {
	o.inc(gvr, ObjectTrackerCallUpdate)
	return o.ObjectTracker.Update(gvr, obj, ns)
}

func (o *ObjectTrackerWithCalls) List(gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, ns string, _ ...metav1.ListOptions) (runtime.Object, error) {
	o.inc(gvr, ObjectTrackerCallList)
	return o.ObjectTracker.List(gvr, gvk, ns)
}

func (o *ObjectTrackerWithCalls) Delete(gvr schema.GroupVersionResource, ns, name string, _ ...metav1.DeleteOptions) error {
	o.inc(gvr, ObjectTrackerCallDelete)
	return o.ObjectTracker.Delete(gvr, ns, name)
}

func (o *ObjectTrackerWithCalls) Watch(gvr schema.GroupVersionResource, ns string, _ ...metav1.ListOptions) (watch.Interface, error) {
	o.inc(gvr, ObjectTrackerCallWatch)
	return o.ObjectTracker.Watch(gvr, ns)
}

type ProxyTestCase struct {
	Lowercase  bool
	Target     string
	PodProxies []*ProxyConfig
}

type ProxyConfig struct {
	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string
}

func PrettyFormatProxyTestCase(testCase ProxyTestCase) string {
	var containerProxies []string
	for _, containerProxy := range testCase.PodProxies {
		if containerProxy == nil {
			containerProxies = append(containerProxies, "nil")
		} else {
			containerProxies = append(containerProxies, fmt.Sprintf("{HTTPProxy: %s, HTTPSProxy: %s, NoProxy: %s}", containerProxy.HTTPProxy, containerProxy.HTTPSProxy, containerProxy.NoProxy))
		}
	}

	return fmt.Sprintf("Lowercase: %v, Target: %s, containerProxies: [%s]", testCase.Lowercase, testCase.Target, strings.Join(containerProxies, ","))
}
