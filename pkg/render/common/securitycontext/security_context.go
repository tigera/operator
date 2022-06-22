// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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

package securitycontext

import (
	"github.com/tigera/operator/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
)

var (
	// It is recommended to choose UID and GID that don't collide with existing system users and groups.
	// Non-system UID and GID range is normally from 1000 to 60000 (Debian derived systems define this
	// in /etc/login.defs). On a normal Linux host, it is unlikely to have more than 10k non-system users.
	// 10001 is chosen based on this assumption.
	RunAsUserID  int64 = 10001
	RunAsGroupID int64 = 10001
)

// NewBaseContext returns the non root non privileged security context that most of the containers running should
// be using.
func NewBaseContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.BoolToPtr(false),
		Privileged:               ptr.BoolToPtr(false),
		RunAsNonRoot:             ptr.BoolToPtr(true),
	}
}

// NewNonPriviledgedUserContext returns the base context with a default user and group.
func NewNonPrivilegedUserContext() *corev1.SecurityContext {
	sc := NewBaseContext()
	sc.RunAsUser = &RunAsUserID
	sc.RunAsGroup = &RunAsGroupID

	return sc
}
