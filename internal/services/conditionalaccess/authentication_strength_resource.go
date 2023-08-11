// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package conditionalaccess

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/hashicorp/go-azure-sdk/sdk/odata"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-azuread/internal/clients"
	"github.com/hashicorp/terraform-provider-azuread/internal/helpers"
	"github.com/hashicorp/terraform-provider-azuread/internal/tf"
	"github.com/hashicorp/terraform-provider-azuread/internal/utils"
	"github.com/hashicorp/terraform-provider-azuread/internal/validate"
	"github.com/manicminer/hamilton/msgraph"
)

func authenticationStrengthResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: authenticationStrengthResourceCreate,
		ReadContext:   authenticationStrengthResourceRead,
		UpdateContext: authenticationStrengthResourceUpdate,
		DeleteContext: authenticationStrengthResourceDelete,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(5 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Update: schema.DefaultTimeout(5 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},

		Importer: tf.ValidateResourceIDPriorToImport(func(id string) error {
			if _, err := uuid.ParseUUID(id); err != nil {
				return fmt.Errorf("specified ID (%q) is not valid: %s", id, err)
			}
			return nil
		}),

		Schema: map[string]*schema.Schema{

			"display_name": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"description": {
				Type:             schema.TypeString,
				Required:         true,
				ValidateDiagFunc: validate.NoEmptyStrings,
			},

			"allowed_combinations": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func authenticationStrengthResourceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).ConditionalAccess.authenticationStrengthClient

	displayName := d.Get("display_name").(string)
	description := d.Get("description").(string)

	if v, ok := d.GetOk("ip"); ok {
		properties := expandIPauthenticationStrength(v.([]interface{}))
		properties.BaseauthenticationStrength = &base

		ipLocation, _, err := client.CreateIP(ctx, *properties)
		if err != nil {
			return tf.ErrorDiagF(err, "Could not create named location")
		}
		if ipLocation.ID == nil || *ipLocation.ID == "" {
			return tf.ErrorDiagF(errors.New("Bad API response"), "Object ID returned for named location is nil/empty")
		}

		d.SetId(*ipLocation.ID)
	} else if v, ok := d.GetOk("country"); ok {
		properties := expandCountryauthenticationStrength(v.([]interface{}))
		properties.BaseauthenticationStrength = &base

		countryLocation, _, err := client.CreateCountry(ctx, *properties)
		if err != nil {
			return tf.ErrorDiagF(err, "Could not create named location")
		}
		if countryLocation.ID == nil || *countryLocation.ID == "" {
			return tf.ErrorDiagF(errors.New("Bad API response"), "Object ID returned for named location is nil/empty")
		}

		d.SetId(*countryLocation.ID)
	} else {
		return tf.ErrorDiagF(errors.New("one of `ip` or `country` must be specified"), "Unable to determine named location type")
	}

	return authenticationStrengthResourceRead(ctx, d, meta)
}

func authenticationStrengthResourceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).ConditionalAccess.authenticationStrengthClient

	base := msgraph.BaseauthenticationStrength{
		ID: utils.String(d.Id()),
	}

	if d.HasChange("display_name") {
		displayName := d.Get("display_name").(string)
		base.DisplayName = &displayName
	}

	var updateRefreshFunc resource.StateRefreshFunc //nolint:staticcheck

	if v, ok := d.GetOk("ip"); ok {
		properties := expandIPauthenticationStrength(v.([]interface{}))
		properties.BaseauthenticationStrength = &base

		if _, err := client.UpdateIP(ctx, *properties); err != nil {
			return tf.ErrorDiagF(err, "Could not update named location with ID %q: %+v", d.Id(), err)
		}

		updateRefreshFunc = func() (interface{}, string, error) {
			result, _, err := client.GetIP(ctx, d.Id(), odata.Query{})
			if err != nil {
				return nil, "Error", err
			}

			if locationRaw := flattenIPauthenticationStrength(result); len(locationRaw) > 0 {
				location := locationRaw[0].(map[string]interface{})
				ip := v.([]interface{})[0].(map[string]interface{})
				if !reflect.DeepEqual(location["ip_ranges"], ip["ip_ranges"]) {
					return "stub", "Pending", nil
				}
				if location["trusted"].(bool) != ip["trusted"].(bool) {
					return "stub", "Pending", nil
				}
			}

			return "stub", "Updated", nil
		}
	}

	if v, ok := d.GetOk("country"); ok {
		properties := expandCountryauthenticationStrength(v.([]interface{}))
		properties.BaseauthenticationStrength = &base

		if _, err := client.UpdateCountry(ctx, *properties); err != nil {
			return tf.ErrorDiagF(err, "Could not update named location with ID %q: %+v", d.Id(), err)
		}

		updateRefreshFunc = func() (interface{}, string, error) {
			result, _, err := client.GetCountry(ctx, d.Id(), odata.Query{})
			if err != nil {
				return nil, "Error", err
			}

			if locationRaw := flattenCountryauthenticationStrength(result); len(locationRaw) > 0 {
				location := locationRaw[0].(map[string]interface{})
				ip := v.([]interface{})[0].(map[string]interface{})
				if !reflect.DeepEqual(location["countries_and_regions"], ip["countries_and_regions"]) {
					return "stub", "Pending", nil
				}
				if location["include_unknown_countries_and_regions"].(bool) != ip["include_unknown_countries_and_regions"].(bool) {
					return "stub", "Pending", nil
				}
			}

			return "stub", "Updated", nil
		}
	}

	log.Printf("[DEBUG] Waiting for named location %q to be updated", d.Id())
	timeout, _ := ctx.Deadline()
	stateConf := &resource.StateChangeConf{ //nolint:staticcheck
		Pending:                   []string{"Pending"},
		Target:                    []string{"Updated"},
		Timeout:                   time.Until(timeout),
		MinTimeout:                5 * time.Second,
		ContinuousTargetOccurence: 5,
		Refresh:                   updateRefreshFunc,
	}
	if _, err := stateConf.WaitForStateContext(ctx); err != nil {
		return tf.ErrorDiagF(err, "waiting for update of named location with ID %q", d.Id())
	}

	return authenticationStrengthResourceRead(ctx, d, meta)
}

func authenticationStrengthResourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).ConditionalAccess.authenticationStrengthClient

	result, status, err := client.Get(ctx, d.Id(), odata.Query{})
	if err != nil {
		if status == http.StatusNotFound {
			log.Printf("[DEBUG] Named Location with Object ID %q was not found - removing from state", d.Id())
			d.SetId("")
			return nil
		}
	}
	if result == nil {
		return tf.ErrorDiagF(errors.New("Bad API response"), "Result is nil")
	}

	location := *result

	if ipnl, ok := location.(msgraph.IPauthenticationStrength); ok {
		if ipnl.ID == nil {
			return tf.ErrorDiagF(errors.New("Bad API response"), "ID is nil for returned IP Named Location")
		}
		d.SetId(*ipnl.ID)
		tf.Set(d, "display_name", ipnl.DisplayName)
		tf.Set(d, "ip", flattenIPauthenticationStrength(&ipnl))
	}

	if cnl, ok := location.(msgraph.CountryauthenticationStrength); ok {
		if cnl.ID == nil {
			return tf.ErrorDiagF(errors.New("Bad API response"), "ID is nil for returned Country Named Location")
		}
		d.SetId(*cnl.ID)
		tf.Set(d, "display_name", cnl.DisplayName)
		tf.Set(d, "country", flattenCountryauthenticationStrength(&cnl))
	}

	return nil
}

func authenticationStrengthResourceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*clients.Client).ConditionalAccess.authenticationStrengthsClient
	authenticationStrengthId := d.Id()

	if _, ok := d.GetOk("ip"); ok {
		resp, status, err := client.GetIP(ctx, authenticationStrengthId, odata.Query{})
		if err != nil {
			if status == http.StatusNotFound {
				log.Printf("[DEBUG] Named Location with ID %q already deleted", authenticationStrengthId)
				return nil
			}

			return tf.ErrorDiagPathF(err, "id", "Retrieving named location with ID %q", authenticationStrengthId)
		}
		if resp != nil && resp.IsTrusted != nil && *resp.IsTrusted {
			properties := msgraph.IPauthenticationStrength{
				BaseauthenticationStrength: &msgraph.BaseauthenticationStrength{
					ID: &authenticationStrengthId,
				},
				IsTrusted: utils.Bool(false),
			}
			if _, err := client.UpdateIP(ctx, properties); err != nil {
				return tf.ErrorDiagF(err, "Updating named location with ID %q", authenticationStrengthId)
			}
		}
	}

	if _, ok := d.GetOk("country"); ok {
		if _, status, err := client.GetCountry(ctx, authenticationStrengthId, odata.Query{}); err != nil {
			if status == http.StatusNotFound {
				log.Printf("[DEBUG] Named Location with ID %q already deleted", authenticationStrengthId)
				return nil
			}

			return tf.ErrorDiagPathF(err, "id", "Retrieving named location with ID %q", authenticationStrengthId)
		}
	}

	status, err := client.Delete(ctx, authenticationStrengthId)
	if err != nil {
		return tf.ErrorDiagPathF(err, "id", "Deleting named location with ID %q, got status %d", authenticationStrengthId, status)
	}

	if err := helpers.WaitForDeletion(ctx, func(ctx context.Context) (*bool, error) {
		defer func() { client.BaseClient.DisableRetries = false }()
		client.BaseClient.DisableRetries = true
		if _, status, err := client.Get(ctx, authenticationStrengthId, odata.Query{}); err != nil {
			if status == http.StatusNotFound {
				return utils.Bool(false), nil
			}
			return nil, err
		}
		return utils.Bool(true), nil
	}); err != nil {
		return tf.ErrorDiagF(err, "waiting for deletion of named location with ID %q", authenticationStrengthId)
	}

	return nil
}
