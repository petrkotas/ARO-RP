package frontend

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"net/http"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/Azure/ARO-RP/pkg/api/admin"
	"github.com/Azure/ARO-RP/pkg/database/cosmosdb"
	"github.com/Azure/ARO-RP/pkg/frontend/middleware"
)

func (f *frontend) getAdminOpenShiftClusters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := ctx.Value(middleware.ContextKeyLog).(*logrus.Entry)
	r.URL.Path = filepath.Dir(r.URL.Path)

	b, err := f._getOpenShiftClusters(ctx, r, f.apis[admin.APIVersion].OpenShiftClusterConverter(), func(skipToken string) (cosmosdb.OpenShiftClusterDocumentIterator, error) {
		return f.dbOpenShiftClusters.List(skipToken), nil
	})

	adminReply(log, w, nil, b, err)
}
