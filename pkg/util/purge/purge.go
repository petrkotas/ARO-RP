package purge

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

// all the purge functions are located here

import (
	"context"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/sirupsen/logrus"

	"github.com/Azure/ARO-RP/pkg/util/azureclient/graphrbac"
	"github.com/Azure/ARO-RP/pkg/util/azureclient/mgmt/authorization"
	"github.com/Azure/ARO-RP/pkg/util/azureclient/mgmt/features"
	"github.com/Azure/ARO-RP/pkg/util/azureclient/mgmt/network"
	"github.com/Azure/ARO-RP/pkg/util/azureclient/mgmt/redhatopenshift"

	mgmtnetwork "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-07-01/network"
	mgmtfeatures "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2019-07-01/features"
)

type checkFn func(mgmtfeatures.ResourceGroup) bool

// ResourceCleaner hold the context required for cleaning
type ResourceCleaner struct {
	Log            *logrus.Entry
	SubscriptionID string
	TenantID       string
	Authorizer     autorest.Authorizer
	DryRun         bool

	DeleteCheck checkFn

	deleteResourceGroups []mgmtfeatures.ResourceGroup
	deletePrivateLinks   []mgmtnetwork.PrivateLinkService
	keepClientIDs        map[string]bool
}

// NewResourceCleaner instantiates the new RC object
func NewResourceCleaner(Log *logrus.Entry, SubscriptionID string, TenantID string, Authorizer autorest.Authorizer, DeleteCheck checkFn, DryRun bool) ResourceCleaner {
	return ResourceCleaner{
		Log:            Log,
		Authorizer:     Authorizer,
		SubscriptionID: SubscriptionID,
		TenantID:       TenantID,
		DryRun:         DryRun,

		// DeleteCheck decides whether the resource group gets deleted
		DeleteCheck: DeleteCheck,
	}
}

// CleanResourceGroup checkes whether the resource group can be deleted if yes proceed to clean the group in an order:
//     - unassign subnets
//     - clean private links
//     - checks ARO presence -> store app object ID for futher use
//     - deletes resource group
func (rc *ResourceCleaner) CleanResourceGroup(ctx context.Context, resourceGroup mgmtfeatures.ResourceGroup) error {
	resourcegroupscli := features.NewResourceGroupsClient(rc.SubscriptionID, rc.Authorizer)

	if rc.DeleteCheck(resourceGroup) {
		rc.Log.Infof("deleting resource group %s", resourceGroup.Name)

		err := rc.cleanNetworking(ctx, resourceGroup)
		if err != nil {
			rc.Log.Errorf("Cannot clean networking: %s", err)
			return err
		}
		err = rc.cleanPrivateLink(ctx, resourceGroup)
		if err != nil {
			rc.Log.Errorf("Cannot clean privatelinks: %s", err)
			return err
		}
		err = rc.checkAndMarkClientID(ctx, resourceGroup)
		if err != nil {
			rc.Log.Errorf("Cannot check for aro cluster: %s", err)
			return err
		}

		if !rc.DryRun {
			_, err := resourcegroupscli.Delete(ctx, *resourceGroup.Name)
			if err != nil {
				rc.Log.Errorf("Cannot delete resourceGroup: %s", resourceGroup.Name, err)
				return err
			}
		}
	}

	return nil
}

// cleanNetworking lists subnets in vnets and unnassign security groups
func (rc *ResourceCleaner) cleanNetworking(ctx context.Context, resourceGroup mgmtfeatures.ResourceGroup) error {
	vnetscli := network.NewVirtualNetworksClient(rc.SubscriptionID, rc.Authorizer)

	vnets, err := vnetscli.List(ctx, *resourceGroup.Name)
	if err != nil {
		rc.Log.Errorf("%s: %s", resourceGroup.Name, err)
		return err
	}

	for _, vnet := range vnets {
		var changed bool

		for i := range *vnet.Subnets {
			if !rc.DryRun {
				(*vnet.Subnets)[i].NetworkSecurityGroup = nil
				changed = true
			} else {
				rc.Log.Infof("Removing NetworkSecurityGroup from vnet: %s, subnet: %s", vnet.Name, (*vnet.Subnets)[i].Name)
				rc.Log.Infof("updating vnet %s/%s", resourceGroup.Name, *vnet.Name)
			}
		}

		if changed {
			rc.Log.Printf("updating vnet %s/%s", resourceGroup.Name, *vnet.Name)
			vnetscli.CreateOrUpdate(ctx, *resourceGroup.Name, *vnet.Name, vnet)
		}
	}

	return nil
}

// cleanPrivateLink lists and unassigns all private links. If they are assigned the deletoin will fail
func (rc *ResourceCleaner) cleanPrivateLink(ctx context.Context, resourceGroup mgmtfeatures.ResourceGroup) error {
	privatelinkservicescli := network.NewPrivateLinkServicesClient(rc.SubscriptionID, rc.Authorizer)
	plss, err := privatelinkservicescli.List(ctx, *resourceGroup.Name)
	if err != nil {
		rc.Log.Errorf("%s: %s", resourceGroup.Name, err)
		return err
	}
	for _, pls := range plss {
		for _, peconn := range *pls.PrivateEndpointConnections {
			rc.Log.Infof("deleting private endpoint connection %s/%s/%s", resourceGroup.Name, *pls.Name, *peconn.Name)
			if !rc.DryRun {
				_, err := privatelinkservicescli.DeletePrivateEndpointConnection(ctx, *resourceGroup.Name, *pls.Name, *peconn.Name)
				if err != nil {
					rc.Log.Errorf("Cannot delete privatelink: %s, %s", pls.Name, err)
					return err
				}
			}
		}
	}

	return nil
}

// CheckAndMarkClientID scans whether the resource group has ARO cluster
// if so, store the attached clientID to enable deletion of
//     - roleAssignment
//     - app registration
// if the cluster is not for deletion, it is flagged to keep.
// Deciding which app and role assignments can be deleted is only possible through linking to the existing cluster.
func (rc *ResourceCleaner) checkAndMarkClientID(ctx context.Context, resourceGroup mgmtfeatures.ResourceGroup) error {
	arocli := redhatopenshift.NewOpenShiftClustersClient(rc.SubscriptionID, rc.Authorizer)

	// list aro clusters if any and append existing app clientID to the delete list
	aros, err := arocli.ListByResourceGroup(ctx, *resourceGroup.Name)
	if err != nil {
		rc.Log.Errorf("%s: %s", resourceGroup.Name, err)
		return err
	}

	// if there is ARO in the resource group, store the app clientID for later cleanup
	for _, aro := range aros {
		clientID := aro.ServicePrincipalProfile.ClientID

		if !rc.DeleteCheck(resourceGroup) {
			if _, ok := rc.keepClientIDs[*clientID]; !ok {
				rc.keepClientIDs[*clientID] = true
			}
		}
	}

	return nil
}

// CleanRoleAssignments lists role assignments from the subscription with name matching the pattern of aro-*
// and deletes everything that is not assigned to the cluster
func (rc *ResourceCleaner) CleanRoleAssignments(ctx context.Context) error {
	roleassignmentcli := authorization.NewRoleAssignmentsClient(rc.SubscriptionID, rc.Authorizer)

	roleAssignments, err := roleassignmentcli.List(ctx, "")
	if err != nil {
		rc.Log.Errorf("Getting roleAssignments: %s", err)
		return err
	}

	// iterate over all roleAssignments and delete everything not assiciated with keep cluster
	for roleAssignments.NotDone() {
		pageResult := roleAssignments.Values()

		for _, roleAssignmentResult := range pageResult {
			if !strings.HasPrefix(*roleAssignmentResult.Name, "aro-") {
				// if the name is not simmilar to the aro cluster pattern, skip
				continue
			}

			_, ok := rc.keepClientIDs[*roleAssignmentResult.PrincipalID]
			if !ok {
				if !rc.DryRun {
					_, err := roleassignmentcli.DeleteByID(ctx, *roleAssignmentResult.ID)
					if err != nil {
						rc.Log.Errorf("Cannot delete roleAssignment %s: %s", *roleAssignmentResult.ID, err)
						return err
					}
				}
				rc.Log.Infof("Deleting role assignment: %s", roleAssignmentResult.Name)
			}
		}

		err := roleAssignments.NextWithContext(ctx)
		if err != nil {
			rc.Log.Errorf("Advancing role assignments failed: %s", err)
			return err
		}
	}

	return nil
}

// CleanApps lists all apps from the subscription with name matching the pattern of aro-*
// and deletes eveything that is not assigned to the cluster
func (rc *ResourceCleaner) CleanApps(ctx context.Context) error {
	applicationscli := graphrbac.NewApplicationsClient(rc.TenantID, rc.Authorizer)

	apps, err := applicationscli.List(ctx, "")
	if err != nil {
		rc.Log.Errorf("Cannot list apps from subscription: %s", err)
		return err
	}

	for apps.NotDone() {
		pageResult := apps.Values()

		for _, app := range pageResult {
			if !strings.HasPrefix(*app.DisplayName, "aro-") {
				// if the name is not similar to aro cluster pattern, skip
				continue
			}

			if _, ok := rc.keepClientIDs[*app.ObjectID]; !ok {
				if !rc.DryRun {
					_, err := applicationscli.Delete(ctx, *app.ObjectID)
					if err != nil {
						rc.Log.Errorf("Cannot delete application: %s", err)
						return err
					}
				}
				rc.Log.Infof("Deleting app: %s", app.DisplayName)
			}
		}

		err := apps.NextWithContext(ctx)
		if err != nil {
			rc.Log.Errorf("Cannot advance app paging: %s", err)
			return err
		}
	}

	return nil
}
