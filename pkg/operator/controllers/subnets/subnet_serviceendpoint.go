package subnets

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"fmt"
	"strings"

	mgmtnetwork "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2020-08-01/network"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/Azure/ARO-RP/pkg/api"
	arov1alpha1 "github.com/Azure/ARO-RP/pkg/operator/apis/aro.openshift.io/v1alpha1"
	"github.com/Azure/ARO-RP/pkg/util/subnet"
)

func (r *reconcileManager) ensureSubnetServiceEndpoints(ctx context.Context, s subnet.Subnet) error {
	if !gatewayEnabled(r.instance) {
		r.log.Debug("Reconciling service endpoints on subnet ", s.ResourceID)

		subnetObject, err := r.subnets.Get(ctx, s.ResourceID)
		if err != nil {
			return err
		}

		if subnetObject == nil { // just in case
			return fmt.Errorf("subnet can't be nil")
		}

		var changed bool
		if subnetObject.SubnetPropertiesFormat == nil {
			subnetObject.SubnetPropertiesFormat = &mgmtnetwork.SubnetPropertiesFormat{}
		}
		if subnetObject.SubnetPropertiesFormat.ServiceEndpoints == nil {
			subnetObject.SubnetPropertiesFormat.ServiceEndpoints = &[]mgmtnetwork.ServiceEndpointPropertiesFormat{}
		}

		for _, endpoint := range api.SubnetsEndpoints {
			var found bool
			for _, se := range *subnetObject.SubnetPropertiesFormat.ServiceEndpoints {
				if strings.EqualFold(*se.Service, endpoint) &&
					se.ProvisioningState == mgmtnetwork.Succeeded {
					found = true
				}
			}
			if !found {
				*subnetObject.SubnetPropertiesFormat.ServiceEndpoints = append(*subnetObject.SubnetPropertiesFormat.ServiceEndpoints, mgmtnetwork.ServiceEndpointPropertiesFormat{
					Service:   to.StringPtr(endpoint),
					Locations: &[]string{"*"},
				})
				changed = true
			}
		}

		if changed {
			err = r.subnets.CreateOrUpdate(ctx, s.ResourceID, subnetObject)
			if err != nil {
				return err
			}
		}
		return nil
	}

	r.log.Debug("Skipping service endpoint reconciliation since egress lockdown is enabled")
	return nil
}

func gatewayEnabled(cluster *arov1alpha1.Cluster) bool {
	return len(cluster.Spec.GatewayDomains) > 0
}
