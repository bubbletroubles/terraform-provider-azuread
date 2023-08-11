// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"github.com/hashicorp/terraform-provider-azuread/internal/common"
	"github.com/manicminer/hamilton/msgraph"
)

type Client struct {
	AuthenticationStrengthClient *msgraph.AuthenticationStrengthClient
	NamedLocationsClient         *msgraph.NamedLocationsClient
	PoliciesClient               *msgraph.ConditionalAccessPoliciesClient
}

func NewClient(o *common.ClientOptions) *Client {
	authenticationStrengthClient := msgraph.NewAuthenticationStrengthClient()
	o.ConfigureClient(&authenticationStrengthClient.BaseClient)

	namedLocationsClient := msgraph.NewNamedLocationsClient()
	o.ConfigureClient(&namedLocationsClient.BaseClient)

	policiesClient := msgraph.NewConditionalAccessPoliciesClient()
	o.ConfigureClient(&policiesClient.BaseClient)

	return &Client{
		AuthenticationStrengthClient: authenticationStrengthClient,
		NamedLocationsClient:         namedLocationsClient,
		PoliciesClient:               policiesClient,
	}
}
