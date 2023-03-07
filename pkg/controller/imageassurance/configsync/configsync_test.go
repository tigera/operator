// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package configsync_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/imageassurance/configsync"
	"github.com/tigera/operator/pkg/controller/utils"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	"github.com/tigera/operator/pkg/render/imageassurance"
	operatortime "github.com/tigera/operator/pkg/time"
	mockoperatortime "github.com/tigera/operator/pkg/time/mocks"

	"github.com/tigera/operator/pkg/bastapi"
	mockbast "github.com/tigera/operator/pkg/bastapi/mocks"
)

func mockIAAPIClientCreator(bastClient bastapi.Client) configsync.BastClientCreator {
	return func(httpClient *http.Client, baseURL string, token string) bastapi.Client {
		return bastClient
	}
}

func mockTickerCreator(ticker operatortime.Ticker) configsync.TickerCreator {
	return func(duration time.Duration) operatortime.Ticker {
		return ticker
	}
}

var _ = Describe("Image Assurance Controller", func() {
	var (
		mockBastClient    *mockbast.Client
		c                 client.Client
		scheme            *runtime.Scheme
		mockTicker        *mockoperatortime.Ticker
		defaultTickerChan chan time.Time
	)

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		// Create a client that will have a crud interface of k8s objects.
		c = fake.NewClientBuilder().WithScheme(scheme).Build()

		mockBastClient = new(mockbast.Client)

		mockTicker = new(mockoperatortime.Ticker)
		defaultTickerChan = make(chan time.Time)
	})

	AfterEach(func() {
		defer close(defaultTickerChan)

		mockBastClient.AssertExpectations(GinkgoT())
		mockTicker.AssertExpectations(GinkgoT())
	})

	When("the service account and config map are available and StartPeriodicSync is called", func() {
		BeforeEach(func() {
			ctx := context.Background()

			Expect(c.Create(ctx, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: imageassurance.OperatorAPIAccessServiceAccountName, Namespace: common.OperatorNamespace()},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      imageassurance.OperatorAPIAccessServiceAccountName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{"token": []byte("token")},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: rcimageassurance.ConfigurationConfigMapName, Namespace: common.OperatorNamespace()},
				Data: map[string]string{
					"organizationID": "tenant123",
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      imageassurance.APICertSecretName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string][]byte{corev1.TLSCertKey: []byte("certbytes")},
			})).NotTo(HaveOccurred())
		})
		It("it immediately polls for the configuration from the IA API and writes it to the config map", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			mockBastClient.On("GetOrganization", "tenant123", mock.Anything).Return(&bastapi.Organization{
				Settings: bastapi.OrganizationSettings{
					RuntimeViewEnabled: true,
				},
			}, nil).Once()

			// This test doesn't necessarily care if these are called, which is why "Maybe" is used. These functions
			// will be called, but it might not be until after the test has finished (we don't wait for the call).
			mockTicker.On("Chan").Return((<-chan time.Time)(defaultTickerChan)).Maybe()
			mockTicker.On("Stop").Return().Maybe()

			syncer := configsync.NewSyncer(ctx, "localhost:9999", c,
				configsync.WithBastClientCreator(mockIAAPIClientCreator(mockBastClient)),
				configsync.WithTickerCreator(mockTickerCreator(mockTicker)),
			)

			syncer.StartPeriodicSync()

			Eventually(func() string {
				configurationConfigMap, err := utils.GetImageAssuranceConfigurationConfigMap(c)
				Expect(err).ShouldNot(HaveOccurred())
				return configurationConfigMap.Data["runtimeViewEnabled"]
			}, 5*time.Second, 100*time.Millisecond).Should(Equal("true"))
		})

		When("the ticker ticks after the initial immediate sync", func() {
			It("syncs the configuration again", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				// To assert that the config is changed by the periodic polling and not the initial sync we initially set
				// the RuntimeViewEnabled value to false, then set it to true on the call for the periodic sync.
				mockBastClient.On("GetOrganization", "tenant123", mock.Anything).Return(&bastapi.Organization{
					Settings: bastapi.OrganizationSettings{
						RuntimeViewEnabled: false,
					},
				}, nil).Once()

				mockBastClient.On("GetOrganization", "tenant123", mock.Anything).Return(&bastapi.Organization{
					Settings: bastapi.OrganizationSettings{
						RuntimeViewEnabled: true,
					},
				}, nil).Once()

				// We count on Chan being called once while this test is running, but we don't know if Stop will be called
				// before the test finishes, so we keep the "Maybe" assertion on Stop.
				mockTicker.On("Chan").Return((<-chan time.Time)(defaultTickerChan)).Once()
				mockTicker.On("Stop").Return().Maybe()

				syncer := configsync.NewSyncer(ctx, "localhost:9999", c,
					configsync.WithBastClientCreator(mockIAAPIClientCreator(mockBastClient)),
					configsync.WithTickerCreator(mockTickerCreator(mockTicker)),
				)

				syncer.StartPeriodicSync()

				Eventually(func() string {
					configurationConfigMap, err := utils.GetImageAssuranceConfigurationConfigMap(c)
					Expect(err).ShouldNot(HaveOccurred())
					return configurationConfigMap.Data["runtimeViewEnabled"]
				}, 5*time.Second, 100*time.Millisecond).Should(Equal("false"))

				defaultTickerChan <- time.Now()

				Eventually(func() string {
					configurationConfigMap, err := utils.GetImageAssuranceConfigurationConfigMap(c)
					Expect(err).ShouldNot(HaveOccurred())
					return configurationConfigMap.Data["runtimeViewEnabled"]
				}, 5*time.Second, 100*time.Millisecond).Should(Equal("true"))
			})
		})

		When("an error occurs", func() {
			var syncer configsync.Syncer
			var cancel func()
			BeforeEach(func() {
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())

				mockBastClient.On("GetOrganization", "tenant123", mock.Anything).Return(nil, fmt.Errorf("some error")).Once()

				// This test doesn't necessarily care if these are called, which is why "Maybe" is used. These functions
				// will be called, but it might not be until after the test has finished (we don't wait for the call).
				mockTicker.On("Chan").Return((<-chan time.Time)(defaultTickerChan)).Maybe()
				mockTicker.On("Stop").Return().Maybe()

				syncer = configsync.NewSyncer(ctx, "localhost:9999", c,
					configsync.WithBastClientCreator(mockIAAPIClientCreator(mockBastClient)),
					configsync.WithTickerCreator(mockTickerCreator(mockTicker)),
				)

				syncer.StartPeriodicSync()
			})

			AfterEach(func() {
				cancel()
			})

			It("is returned through the Error() function", func() {
				Expect(syncer.Error()).ShouldNot(BeNil())
			})

			When("the error doesn't happen on the next tick", func() {
				It("returns nil when Error() is called", func() {
					Expect(syncer.Error()).ShouldNot(BeNil())

					mockBastClient.On("GetOrganization", "tenant123", mock.Anything).Return(&bastapi.Organization{
						Settings: bastapi.OrganizationSettings{
							RuntimeViewEnabled: false,
						},
					}, nil).Once()

					defaultTickerChan <- time.Now()
					Expect(syncer.Error()).Should(BeNil())
				})
			})
		})
	})

	When("the context is cancelled", func() {
		It("shuts down the syncer", func() {
			ctx, cancel := context.WithCancel(context.Background())
			syncer := configsync.NewSyncer(ctx, "localhost:9999", c,
				configsync.WithBastClientCreator(mockIAAPIClientCreator(mockBastClient)),
			)

			cancel()

			// We test that panic occurred when calling StartPeriodicSync after the context has been cancelled. It's
			// invalid to call StartPeriodicSync after the context has been cancelled as cancelling the context shuts down
			// the syncer.
			Eventually(func() bool {
				panicked := false

				func() {
					defer func() {
						if r := recover(); r != nil {
							panicked = true
						}
					}()
					syncer.StartPeriodicSync()
				}()

				return panicked
			}, 2*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})
})
