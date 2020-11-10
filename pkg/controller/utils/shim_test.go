package utils

import (
	"net/http"

	"github.com/olivere/elastic/v7"
	. "github.com/onsi/gomega"
)

func NewElasticClientShims(h *http.Client, url string) esClient {
	options := []elastic.ClientOptionFunc{
		elastic.SetHttpClient(h),
		elastic.SetURL(url),
		elastic.SetSniff(false),
	}
	client, err := elastic.NewClient(options...)
	Expect(err).To(BeNil())

	ecl := esClient{}
	ecl.client = client
	return ecl
}
