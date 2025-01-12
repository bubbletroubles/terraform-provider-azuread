package msgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

// AuthenticationStrengthPoliciesClient performs operations on AuthenticationStrengthPolicy.
type AuthenticationStrengthPoliciesClient struct {
	BaseClient Client
}

// NewAuthenticationStrengthPoliciesClient returns a new AuthenticationStrengthPoliciesClient
func NewAuthenticationStrengthPoliciesClient() *AuthenticationStrengthPoliciesClient {
	return &AuthenticationStrengthPoliciesClient{
		BaseClient: NewClient(VersionBeta),
	}
}

// List returns a list of AuthenticationStrengthPolicy, optionally queried using OData.
func (c *AuthenticationStrengthPoliciesClient) List(ctx context.Context, query odata.Query) (*[]AuthenticationStrengthPolicy, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		OData:            query,
		ValidStatusCodes: []int{http.StatusOK},
		Uri: Uri{
			Entity: "/policies/authenticationStrengthPolicies",
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("AuthenticationStrengthPoliciesClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var data struct {
		AuthenticationStrengthPolicys []AuthenticationStrengthPolicy `json:"value"`
	}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &data.AuthenticationStrengthPolicys, status, nil
}

// Create creates a new AuthenticationStrengthPolicy.
func (c *AuthenticationStrengthPoliciesClient) Create(ctx context.Context, authenticationStrengthPolicy AuthenticationStrengthPolicy) (*AuthenticationStrengthPolicy, int, error) {
	var status int
	body, err := json.Marshal(authenticationStrengthPolicy)
	if err != nil {
		return nil, status, fmt.Errorf("json.Marshal(): %v", err)
	}

	resp, status, _, err := c.BaseClient.Post(ctx, PostHttpRequestInput{
		Body:             body,
		ValidStatusCodes: []int{http.StatusCreated},
		Uri: Uri{
			Entity: "/policies/authenticationStrengthPolicies",
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("AuthenticationStrengthPoliciesClient.BaseClient.Post(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var newAuthenticationStrengthPolicy AuthenticationStrengthPolicy
	if err := json.Unmarshal(respBody, &newAuthenticationStrengthPolicy); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &newAuthenticationStrengthPolicy, status, nil
}

// Get retrieves a AuthenticationStrengthPolicy.
func (c *AuthenticationStrengthPoliciesClient) Get(ctx context.Context, id string, query odata.Query) (*AuthenticationStrengthPolicy, int, error) {
	resp, status, _, err := c.BaseClient.Get(ctx, GetHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		OData:                  query,
		ValidStatusCodes:       []int{http.StatusOK},
		Uri: Uri{
			Entity: fmt.Sprintf("/policies/authenticationStrengthPolicies/%s", id),
		},
	})
	if err != nil {
		return nil, status, fmt.Errorf("AuthenticationStrengthPoliciesClient.BaseClient.Get(): %v", err)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, status, fmt.Errorf("io.ReadAll(): %v", err)
	}

	var AuthenticationStrengthPolicy AuthenticationStrengthPolicy
	if err := json.Unmarshal(respBody, &AuthenticationStrengthPolicy); err != nil {
		return nil, status, fmt.Errorf("json.Unmarshal(): %v", err)
	}

	return &AuthenticationStrengthPolicy, status, nil
}

// Update amends an existing AuthenticationStrengthPolicy.
func (c *AuthenticationStrengthPoliciesClient) Update(ctx context.Context, AuthenticationStrengthPolicy AuthenticationStrengthPolicy) (int, error) {
	var status int

	if AuthenticationStrengthPolicy.ID == nil {
		return status, errors.New("cannot update AuthenticationStrengthPolicy with nil ID")
	}

	body, err := json.Marshal(AuthenticationStrengthPolicy)
	if err != nil {
		return status, fmt.Errorf("json.Marshal(): %v", err)
	}

	_, status, _, err = c.BaseClient.Patch(ctx, PatchHttpRequestInput{
		Body:                   body,
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusNoContent},
		Uri: Uri{
			Entity: fmt.Sprintf("/policies/authenticationStrengthPolicies/%s", *AuthenticationStrengthPolicy.ID),
		},
	})
	if err != nil {
		return status, fmt.Errorf("AuthenticationStrengthPoliciesClient.BaseClient.Patch(): %v", err)
	}

	return status, nil
}

// Delete removes a AuthenticationStrengthPolicy.
func (c *AuthenticationStrengthPoliciesClient) Delete(ctx context.Context, id string) (int, error) {
	_, status, _, err := c.BaseClient.Delete(ctx, DeleteHttpRequestInput{
		ConsistencyFailureFunc: RetryOn404ConsistencyFailureFunc,
		ValidStatusCodes:       []int{http.StatusNoContent},
		Uri: Uri{
			Entity: fmt.Sprintf("/policies/authenticationStrengthPolicies/%s/$ref", id),
		},
	})
	if err != nil {
		return status, fmt.Errorf("AuthenticationStrengthPoliciesClient.BaseClient.Delete(): %v", err)
	}

	return status, nil
}
