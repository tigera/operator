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

package whisker

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
)

const ingressGatewayWarning = "ingressgateway-variant"

// Extension is the Calico Enterprise behavior for the whisker controller.
type Extension struct {
	variant operatorv1.ProductVariant
}

var _ extensions.WhiskerExtension = &Extension{}

// New returns the whisker extension for the variant the operator resolved.
func New(variant operatorv1.ProductVariant) *Extension {
	return &Extension{variant: variant}
}

// ValidateAndDefault drops spec.ingressGateway, which only Calico's whisker serves.
func (e *Extension) ValidateAndDefault(cr *operatorv1.Whisker, st status.StatusManager) error {
	if cr.Spec.IngressGateway == nil {
		st.ClearWarning(ingressGatewayWarning)
		return nil
	}

	st.SetWarning(ingressGatewayWarning,
		"spec.ingressGateway on the Whisker resource is ignored on Calico Enterprise; expose the UI through the Manager resource's spec.ingressGateway instead")
	cr.Spec.IngressGateway = nil
	return nil
}

// Modify is a no-op: the whisker render component shapes its objects per
// variant itself, and Enterprise deploys whisker-backend.
func (e *Extension) Modify(c render.Component, ri render.Inputs) render.Component {
	return c
}
