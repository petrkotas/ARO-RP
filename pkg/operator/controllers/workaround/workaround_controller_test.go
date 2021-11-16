package workaround

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	configv1 "github.com/openshift/api/config/v1"
	configfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	arov1alpha1 "github.com/Azure/ARO-RP/pkg/operator/apis/aro.openshift.io/v1alpha1"
	aroclient "github.com/Azure/ARO-RP/pkg/operator/clientset/versioned"
	arofake "github.com/Azure/ARO-RP/pkg/operator/clientset/versioned/fake"
	utillog "github.com/Azure/ARO-RP/pkg/util/log"
	mock_workaround "github.com/Azure/ARO-RP/pkg/util/mocks/operator/controllers/workaround"
)

func clusterVersion(ver string) *configv1.ClusterVersion {
	return &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name: "version",
		},
		Status: configv1.ClusterVersionStatus{
			Desired: configv1.Release{
				Version: ver,
			},
			History: []configv1.UpdateHistory{
				{
					State:   configv1.CompletedUpdate,
					Version: ver,
				},
			},
		},
	}
}

func TestWorkaroundReconciler(t *testing.T) {

	arocli := arofake.NewSimpleClientset(&arov1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: arov1alpha1.SingletonClusterName,
		},
		Spec: arov1alpha1.ClusterSpec{
			Features: arov1alpha1.FeaturesSpec{
				ReconcileWorkaroundsController: true,
			},
		},
	})

	tests := []struct {
		name    string
		want    ctrl.Result
		mocker  func(mw *mock_workaround.MockWorkaround)
		arocli  aroclient.Interface
		wantErr bool
	}{
		{
			name: "is required",
			mocker: func(mw *mock_workaround.MockWorkaround) {
				gomock.InOrder(
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(true),
					mw.EXPECT().Ensure(gomock.Any()).Return(nil),
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(true),
					mw.EXPECT().Ensure(gomock.Any()).Return(nil),
				)
			},
			arocli: arocli,
			want:   ctrl.Result{Requeue: true, RequeueAfter: time.Hour},
		},
		{
			name: "is not required",
			mocker: func(mw *mock_workaround.MockWorkaround) {
				gomock.InOrder(
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(false),
					mw.EXPECT().Remove(gomock.Any()).Return(nil),
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(false),
					mw.EXPECT().Remove(gomock.Any()).Return(nil),
				)
			},
			arocli: arocli,
			want:   ctrl.Result{Requeue: true, RequeueAfter: time.Hour},
		},
		{
			name: "has error",
			mocker: func(mw *mock_workaround.MockWorkaround) {
				mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(true)
				mw.EXPECT().Name().Return("test").AnyTimes()
				mw.EXPECT().Ensure(gomock.Any()).Return(fmt.Errorf("oops"))
			},
			want:    ctrl.Result{},
			arocli:  arocli,
			wantErr: true,
		},
		{
			name: "systemReserved is not required because autoNodeSizing is enabled",
			mocker: func(mw *mock_workaround.MockWorkaround) {
				gomock.InOrder(
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(false),
					mw.EXPECT().Remove(gomock.Any()).Return(nil),
					mw.EXPECT().IsRequired(gomock.Any(), gomock.Any()).Return(true),
					mw.EXPECT().Ensure(gomock.Any()).Return(nil),
				)
			},
			arocli: arofake.NewSimpleClientset(&arov1alpha1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: arov1alpha1.SingletonClusterName,
				},
				Spec: arov1alpha1.ClusterSpec{
					Features: arov1alpha1.FeaturesSpec{
						ReconcileWorkaroundsController: true,
						ReconcileAutoSizedNodes:        true,
					},
				},
			}),
			want: ctrl.Result{Requeue: true, RequeueAfter: time.Hour},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()

			mwa := mock_workaround.NewMockWorkaround(controller)
			workarounds := map[string]Workaround{
				"test":           mwa,
				"systemReserved": mwa,
			}
			r := &Reconciler{
				arocli:      tt.arocli,
				configcli:   configfake.NewSimpleClientset(clusterVersion("4.4.10")),
				workarounds: workarounds,
				log:         utillog.GetLogger(),
			}
			tt.mocker(mwa)
			got, err := r.Reconcile(context.Background(), reconcile.Request{})
			if (err != nil) != tt.wantErr {
				t.Errorf("WorkaroundReconciler.Reconcile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WorkaroundReconciler.Reconcile() = %v, want %v", got, tt.want)
			}
		})
	}
}
