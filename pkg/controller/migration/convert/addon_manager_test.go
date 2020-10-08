package convert

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "github.com/tigera/operator/api/v1"
)

var _ = Describe("addon manager", func() {
	addonMgrLabel := map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"}

	It("should succeed if addon manager isn't denoted", func() {
		comps := emptyComponents()
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).ToNot(HaveOccurred())
	})
	It("should fail if calico-node is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.node.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
	It("should fail if kube-controllers is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.kubeControllers.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
	It("should fail if typha is managed by addon-manager", func() {
		comps := emptyComponents()
		comps.typha.Labels = addonMgrLabel
		i := v1.Installation{}
		Expect(handleAddonManager(&comps, &i)).To(HaveOccurred())
	})
})
