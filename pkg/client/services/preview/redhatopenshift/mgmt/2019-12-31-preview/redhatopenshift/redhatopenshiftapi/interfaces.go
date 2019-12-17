package redhatopenshiftapi

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"

	"github.com/Azure/ARO-RP/pkg/client/services/preview/redhatopenshift/mgmt/2019-12-31-preview/redhatopenshift"
)

// OperationsClientAPI contains the set of methods on the OperationsClient type.
type OperationsClientAPI interface {
	List(ctx context.Context) (result redhatopenshift.OperationList, err error)
}

var _ OperationsClientAPI = (*redhatopenshift.OperationsClient)(nil)

// OpenShiftClustersClientAPI contains the set of methods on the OpenShiftClustersClient type.
type OpenShiftClustersClientAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters redhatopenshift.OpenShiftCluster) (result redhatopenshift.OpenShiftClustersCreateOrUpdateFuture, err error)
	Delete(ctx context.Context, resourceGroupName string, resourceName string) (result redhatopenshift.OpenShiftClustersDeleteFuture, err error)
	Get(ctx context.Context, resourceGroupName string, resourceName string) (result redhatopenshift.OpenShiftCluster, err error)
	GetCredentials(ctx context.Context, resourceGroupName string, resourceName string) (result redhatopenshift.OpenShiftClusterCredentials, err error)
	List(ctx context.Context) (result redhatopenshift.OpenShiftClusterList, err error)
	ListByResourceGroup(ctx context.Context, resourceGroupName string) (result redhatopenshift.OpenShiftClusterList, err error)
	Update(ctx context.Context, resourceGroupName string, resourceName string, parameters redhatopenshift.OpenShiftCluster) (result redhatopenshift.OpenShiftClustersUpdateFuture, err error)
}

var _ OpenShiftClustersClientAPI = (*redhatopenshift.OpenShiftClustersClient)(nil)
