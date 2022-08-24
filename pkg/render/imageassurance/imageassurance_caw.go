// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *component) cawDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ResourceNameImageAssuranceCAW,
			Namespace: NameSpaceImageAssurance,
		},
	}
}
