package podsecuritycontext

import (
	"github.com/tigera/operator/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
)

// NewBaseContext returns the non root non privileged security context that most of the containers running should
// be using.
func NewBaseContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsNonRoot:             ptr.BoolToPtr(true),
		AllowPrivilegeEscalation: ptr.BoolToPtr(false),
	}
}
