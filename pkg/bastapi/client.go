// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package bastapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Organization struct {
	ID       string               `json:"id"`
	Name     string               `json:"name" validate:"required"`
	Settings OrganizationSettings `json:"settings" validate:"required"`
}

type OrganizationSettings struct {
	ThresholdCVSSPass              float64 `json:"thresholdCVSSPass"`
	ThresholdCVSSWarn              float64 `json:"thresholdCVSSWarn"`
	ContinuousAssuranceIntervalHrs int     `json:"continuousAssuranceIntervalHrs"`
	RuntimeViewEnabled             bool    `json:"runtimeViewEnabled"`
}

type Client interface {
	GetOrganization(organizationID string) (*Organization, error)
}

type client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

const (
	organizationURI = "v1/organizations/%s"
)

func NewClient(httpClient *http.Client, baseURL string, token string) Client {
	return &client{
		httpClient: httpClient,
		baseURL:    baseURL,
		token:      token,
	}
}

func (c client) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token))

	return request, nil
}

// GetOrganization retrieves the single organization that correspond to the organization ID.
func (c client) GetOrganization(organizationID string) (*Organization, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, organizationURI)

	request, err := c.newRequest("GET", fmt.Sprintf(url, organizationID), nil)
	if err != nil {
		return nil, err
	}

	var organizationDTO Organization

	resp, fetchOrgErr := c.httpClient.Do(request)
	if fetchOrgErr != nil {
		return nil, fetchOrgErr
	}
	defer resp.Body.Close()
	if fetchOrgErr = parseResponse(resp, &organizationDTO); fetchOrgErr != nil {
		return nil, fetchOrgErr
	}

	return &organizationDTO, nil
}

func parseResponse(resp *http.Response, obj interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("%s %d", body, resp.StatusCode)
	}

	if err := json.Unmarshal(body, obj); err != nil {
		return err
	}

	return nil
}
