// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package imageassurance

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/onsi/ginkgo/reporters"
	uzap "go.uber.org/zap"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestStatus(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true), zap.Level(uzap.NewAtomicLevelAt(uzap.DebugLevel))))
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/imageassurance_controller_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/controller/Image Assurance Controller Suite", []Reporter{junitReporter})
}
