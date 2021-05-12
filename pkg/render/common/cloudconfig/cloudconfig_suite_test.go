package cloudconfig

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/onsi/ginkgo/reporters"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestStatus(t *testing.T) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter)))
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/cloudconfig_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "pkg/render/common/cloudconfig/CloudConfig Suite", []Reporter{junitReporter})
}
