// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package render

import (
	"testing"

	uzap "go.uber.org/zap"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// The operator registers the Enterprise images as it builds the Enterprise
// extensions, so a suite with Enterprise-variant specs registers them too.
var _ = ginkgo.BeforeSuite(func() {
	components.RegisterVariantImages(operatorv1.CalicoEnterprise, components.EnterpriseImages)
})

func TestRender(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(ginkgo.GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/ut/render_suite.xml"
	ginkgo.RunSpecs(t, "pkg/render Suite", suiteConfig, reporterConfig)
}
