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

package test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Shared helpers for the dataplane-disabled "real-life usage" FV specs (see no_dataplane_test.go).
// They deploy lightweight, publicly-pullable workloads and drive real HTTP traffic
// between in-cluster pods so the specs can assert on the behaviour of the Calico
// Ingress Gateway data path and the Calico Istio ambient mesh — not just that the
// control-plane components installed.

const (
	// httpEchoImage is a tiny HTTP server that echoes a fixed string on every path,
	// which lets a routing test tell which backend served a request.
	httpEchoImage = "hashicorp/http-echo:0.2.3"
	// curlImage is a minimal image with curl; we run it with `sleep` so we can exec
	// curl into it on demand to generate traffic.
	curlImage = "curlimages/curl:8.11.1"
	// echoPort is the port the http-echo backends listen on.
	echoPort = 8080
)

// curlResult is the outcome of a curl run inside a pod.
type curlResult struct {
	// Code is the HTTP status code reported by curl's `-w %{http_code}`. It is "000"
	// when no response was received (e.g. the connection was reset by a mesh policy).
	Code string
	// Body is everything curl wrote to stdout before the status-code line.
	Body string
}

// createIgnoreExists creates obj, tolerating an AlreadyExists error so the helpers
// are safe to call across retries and re-runs.
func createIgnoreExists(c client.Client, obj client.Object) {
	err := c.Create(context.Background(), obj)
	if err != nil && !kerror.IsAlreadyExists(err) {
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
}

// ensureNamespace creates a namespace with the given labels if it does not already exist.
func ensureNamespace(c client.Client, name string, labels map[string]string) {
	createIgnoreExists(c, &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	})
}

// deleteNamespace best-effort deletes a namespace; used in spec cleanup.
func deleteNamespace(c client.Client, name string) {
	_ = c.Delete(context.Background(), &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
}

// deployHTTPEcho creates a single-replica http-echo Deployment plus a matching
// ClusterIP Service, both named name, that respond to every path with responseText.
func deployHTTPEcho(c client.Client, namespace, name, responseText string) {
	labels := map[string]string{"app": name}
	replicas := int32(1)
	createIgnoreExists(c, &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "http-echo",
						Image: httpEchoImage,
						Args: []string{
							fmt.Sprintf("-text=%s", responseText),
							fmt.Sprintf("-listen=:%d", echoPort),
						},
						Ports: []corev1.ContainerPort{{ContainerPort: int32(echoPort)}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/",
									Port: intstr.FromInt(echoPort),
								},
							},
						},
					}},
				},
			},
		},
	})

	createIgnoreExists(c, &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Port:       int32(echoPort),
				TargetPort: intstr.FromInt(echoPort),
			}},
		},
	})
}

// deployCurlClient creates a long-lived pod that we can exec curl into to generate traffic.
func deployCurlClient(c client.Client, namespace, name string) {
	labels := map[string]string{"app": name}
	createIgnoreExists(c, &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "curl",
				Image:   curlImage,
				Command: []string{"sleep", "infinity"},
			}},
		},
	})
}

// waitForDeploymentAvailable waits until the named Deployment reports an available replica.
func waitForDeploymentAvailable(c client.Client, namespace, name string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := GetResource(c, d); err != nil {
			return err
		}
		if d.Status.AvailableReplicas < 1 {
			return fmt.Errorf("deployment %s/%s has no available replicas yet", namespace, name)
		}
		return nil
	}, timeout).ShouldNot(HaveOccurred())
}

// waitForPodReady waits until the named pod reports the Ready condition.
func waitForPodReady(c client.Client, namespace, name string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := GetResource(c, p); err != nil {
			return err
		}
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("pod %s/%s not ready yet (phase=%s)", namespace, name, p.Status.Phase)
	}, timeout).ShouldNot(HaveOccurred())
}

// waitForDaemonSetReady waits until every scheduled pod of the named DaemonSet is ready.
// Istio's istio-cni and ztunnel run as DaemonSets and must be fully ready before mesh
// workloads start, since pod enrollment happens at pod-creation time on each node.
func waitForDaemonSetReady(c client.Client, namespace, name string, timeout time.Duration) {
	EventuallyWithOffset(1, func() error {
		ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := GetResource(c, ds); err != nil {
			return err
		}
		if ds.Status.DesiredNumberScheduled == 0 || ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
			return fmt.Errorf("daemonset %s/%s not fully ready (%d/%d)", namespace, name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
		}
		return nil
	}, timeout).ShouldNot(HaveOccurred())
}

// execInPod runs command in a container of a pod and returns its stdout and stderr.
// A non-zero exit from the command is returned as a non-nil error; the buffers still
// hold whatever the command wrote, so callers can inspect partial output.
func execInPod(cfg *rest.Config, namespace, podName, container string, command []string) (string, string, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", "", err
	}
	req := cs.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return stdout.String(), stderr.String(), err
}

// runCurl execs curl inside clientPod against url and returns the parsed result.
// extraArgs are inserted before the URL (e.g. -H "Host: ..."). A non-nil error is
// returned when curl exits non-zero (for example when a mesh policy resets the
// connection); the returned curlResult is still populated from curl's -w output so
// callers can assert on the status code regardless.
func runCurl(cfg *rest.Config, namespace, clientPod, url string, extraArgs ...string) (curlResult, error) {
	args := []string{"curl", "-sS", "--max-time", "10", "-o", "/dev/stdout", "-w", "\n%{http_code}"}
	args = append(args, extraArgs...)
	args = append(args, url)

	stdout, stderr, err := execInPod(cfg, namespace, clientPod, "curl", args)
	res := parseCurlOutput(stdout)
	if err != nil {
		return res, fmt.Errorf("curl %q failed: %w (stderr=%q)", url, err, stderr)
	}
	return res, nil
}

// parseCurlOutput splits curl's combined stdout into the trailing status-code line
// (written by `-w "\n%{http_code}"`) and the response body that precedes it.
func parseCurlOutput(stdout string) curlResult {
	trimmed := strings.TrimRight(stdout, "\r\n")
	if i := strings.LastIndexByte(trimmed, '\n'); i >= 0 {
		return curlResult{Code: strings.TrimSpace(trimmed[i+1:]), Body: trimmed[:i]}
	}
	return curlResult{Code: strings.TrimSpace(trimmed)}
}

// gatewayServiceClusterIP returns the ClusterIP of the data-plane Service that
// envoy-gateway provisions for the named Gateway, or an error if it isn't ready yet.
func gatewayServiceClusterIP(c client.Client, gwNamespace, gwName string) (string, error) {
	var svcs corev1.ServiceList
	if err := c.List(context.Background(), &svcs,
		client.InNamespace(gwNamespace),
		client.MatchingLabels{"gateway.envoyproxy.io/owning-gateway-name": gwName},
	); err != nil {
		return "", err
	}
	for i := range svcs.Items {
		ip := svcs.Items[i].Spec.ClusterIP
		if ip != "" && ip != corev1.ClusterIPNone {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no data-plane Service with a ClusterIP for Gateway %s/%s yet", gwNamespace, gwName)
}

// denyAllAuthorizationPolicy builds an Istio AuthorizationPolicy (as unstructured, since
// the Istio Go types are not vendored) that denies all traffic to workloads matching
// selectorLabels in namespace. In the ambient mesh this is enforced by ztunnel.
func denyAllAuthorizationPolicy(namespace, name string, selectorLabels map[string]string) *unstructured.Unstructured {
	matchLabels := map[string]any{}
	for k, v := range selectorLabels {
		matchLabels[k] = v
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1",
		Kind:    "AuthorizationPolicy",
	})
	u.SetNamespace(namespace)
	u.SetName(name)
	u.Object["spec"] = map[string]any{
		"selector": map[string]any{"matchLabels": matchLabels},
		"action":   "DENY",
		// An empty rule matches every request, so this denies all traffic to the
		// selected workload.
		"rules": []any{map[string]any{}},
	}
	return u
}
