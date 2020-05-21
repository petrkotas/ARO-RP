package main

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/sirupsen/logrus"

	utillog "github.com/Azure/ARO-RP/pkg/util/log"

	"github.com/Azure/ARO-RP/pkg/util/purge"

	mgmtfeatures "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2019-07-01/features"
)

const (
	defaultTTL     = 48
	defaultKeepTag = "KEEPIT"
)

func main() {
	ctx := context.Background()
	log := utillog.GetLogger()

	if err := run(ctx, log); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, log *logrus.Entry) error {

	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	tenantID := os.Getenv("AZURE_TENANT_ID")

	ttl, err := time.ParseDuration(os.Getenv("AZURE_PURGE_TTL"))
	if err != nil {
		// in case of error the default ttl is always 48 hours
		ttl = defaultTTL * time.Hour
		log.Errorf("Cannot convert TTL to int: %s", err)
	}

	doNotTouchTag := os.Getenv("AZURE_KEEP_TAG")
	if doNotTouchTag == "" {
		doNotTouchTag = defaultKeepTag
	}

	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}

	dryRun, err := strconv.ParseBool(os.Getenv("AZURE_PURGE_DRY_RUN"))
	if err != nil {
		log.Errorf("Cannot determine dryRun, defaulting to false: %s", err)
	}
	if dryRun {
		log.Info("Dry run!")
	}

	deleteCheck := func(resourceGroup mgmtfeatures.ResourceGroup) bool {
		if !strings.HasPrefix(*resourceGroup.Name, "v4-e2e-rg-") &&
			!strings.HasPrefix(*resourceGroup.Name, "aro-v4-e2e-rg-") {
			return false
		}

		if _, ok := resourceGroup.Tags[doNotTouchTag]; ok {
			return false
		}

		if resourceGroup.Tags["now"] == nil {
			return false
		}

		now, err := time.Parse(time.RFC3339Nano, *resourceGroup.Tags["now"])
		if err != nil {
			log.Errorf("%s: %s", *resourceGroup.Name, err)
			return false
		}
		if time.Now().Sub(now) < ttl*time.Hour {
			return false
		}

		return true
	}

	rc := purge.NewResourceCleaner(log, subscriptionID, tenantID, authorizer, deleteCheck, dryRun)

	err = rc.CleanResourceGroups(ctx)
	if err != nil {
		return err
	}

	err = rc.CleanRoleAssignments(ctx)
	if err != nil {
		return err
	}

	return rc.CleanApps(ctx)
}
