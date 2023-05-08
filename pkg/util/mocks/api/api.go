// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/ARO-RP/pkg/api (interfaces: SyncSetConverter,MachinePoolConverter,SyncIdentityProviderConverter,SecretConverter)

// Package mock_api is a generated GoMock package.
package mock_api

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"

	api "github.com/Azure/ARO-RP/pkg/api"
)

// MockSyncSetConverter is a mock of SyncSetConverter interface.
type MockSyncSetConverter struct {
	ctrl     *gomock.Controller
	recorder *MockSyncSetConverterMockRecorder
}

// MockSyncSetConverterMockRecorder is the mock recorder for MockSyncSetConverter.
type MockSyncSetConverterMockRecorder struct {
	mock *MockSyncSetConverter
}

// NewMockSyncSetConverter creates a new mock instance.
func NewMockSyncSetConverter(ctrl *gomock.Controller) *MockSyncSetConverter {
	mock := &MockSyncSetConverter{ctrl: ctrl}
	mock.recorder = &MockSyncSetConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSyncSetConverter) EXPECT() *MockSyncSetConverterMockRecorder {
	return m.recorder
}

// ToExternal mocks base method.
func (m *MockSyncSetConverter) ToExternal(arg0 *api.SyncSet) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternal", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternal indicates an expected call of ToExternal.
func (mr *MockSyncSetConverterMockRecorder) ToExternal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternal", reflect.TypeOf((*MockSyncSetConverter)(nil).ToExternal), arg0)
}

// ToExternalList mocks base method.
func (m *MockSyncSetConverter) ToExternalList(arg0 []*api.SyncSet) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternalList", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternalList indicates an expected call of ToExternalList.
func (mr *MockSyncSetConverterMockRecorder) ToExternalList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternalList", reflect.TypeOf((*MockSyncSetConverter)(nil).ToExternalList), arg0)
}

// ToInternal mocks base method.
func (m *MockSyncSetConverter) ToInternal(arg0 interface{}, arg1 *api.SyncSet) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ToInternal", arg0, arg1)
}

// ToInternal indicates an expected call of ToInternal.
func (mr *MockSyncSetConverterMockRecorder) ToInternal(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToInternal", reflect.TypeOf((*MockSyncSetConverter)(nil).ToInternal), arg0, arg1)
}

// MockMachinePoolConverter is a mock of MachinePoolConverter interface.
type MockMachinePoolConverter struct {
	ctrl     *gomock.Controller
	recorder *MockMachinePoolConverterMockRecorder
}

// MockMachinePoolConverterMockRecorder is the mock recorder for MockMachinePoolConverter.
type MockMachinePoolConverterMockRecorder struct {
	mock *MockMachinePoolConverter
}

// NewMockMachinePoolConverter creates a new mock instance.
func NewMockMachinePoolConverter(ctrl *gomock.Controller) *MockMachinePoolConverter {
	mock := &MockMachinePoolConverter{ctrl: ctrl}
	mock.recorder = &MockMachinePoolConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMachinePoolConverter) EXPECT() *MockMachinePoolConverterMockRecorder {
	return m.recorder
}

// ToExternal mocks base method.
func (m *MockMachinePoolConverter) ToExternal(arg0 *api.MachinePool) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternal", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternal indicates an expected call of ToExternal.
func (mr *MockMachinePoolConverterMockRecorder) ToExternal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternal", reflect.TypeOf((*MockMachinePoolConverter)(nil).ToExternal), arg0)
}

// ToExternalList mocks base method.
func (m *MockMachinePoolConverter) ToExternalList(arg0 []*api.MachinePool) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternalList", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternalList indicates an expected call of ToExternalList.
func (mr *MockMachinePoolConverterMockRecorder) ToExternalList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternalList", reflect.TypeOf((*MockMachinePoolConverter)(nil).ToExternalList), arg0)
}

// ToInternal mocks base method.
func (m *MockMachinePoolConverter) ToInternal(arg0 interface{}, arg1 *api.MachinePool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ToInternal", arg0, arg1)
}

// ToInternal indicates an expected call of ToInternal.
func (mr *MockMachinePoolConverterMockRecorder) ToInternal(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToInternal", reflect.TypeOf((*MockMachinePoolConverter)(nil).ToInternal), arg0, arg1)
}

// MockSyncIdentityProviderConverter is a mock of SyncIdentityProviderConverter interface.
type MockSyncIdentityProviderConverter struct {
	ctrl     *gomock.Controller
	recorder *MockSyncIdentityProviderConverterMockRecorder
}

// MockSyncIdentityProviderConverterMockRecorder is the mock recorder for MockSyncIdentityProviderConverter.
type MockSyncIdentityProviderConverterMockRecorder struct {
	mock *MockSyncIdentityProviderConverter
}

// NewMockSyncIdentityProviderConverter creates a new mock instance.
func NewMockSyncIdentityProviderConverter(ctrl *gomock.Controller) *MockSyncIdentityProviderConverter {
	mock := &MockSyncIdentityProviderConverter{ctrl: ctrl}
	mock.recorder = &MockSyncIdentityProviderConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSyncIdentityProviderConverter) EXPECT() *MockSyncIdentityProviderConverterMockRecorder {
	return m.recorder
}

// ToExternal mocks base method.
func (m *MockSyncIdentityProviderConverter) ToExternal(arg0 *api.SyncIdentityProvider) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternal", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternal indicates an expected call of ToExternal.
func (mr *MockSyncIdentityProviderConverterMockRecorder) ToExternal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternal", reflect.TypeOf((*MockSyncIdentityProviderConverter)(nil).ToExternal), arg0)
}

// ToExternalList mocks base method.
func (m *MockSyncIdentityProviderConverter) ToExternalList(arg0 []*api.SyncIdentityProvider) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternalList", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternalList indicates an expected call of ToExternalList.
func (mr *MockSyncIdentityProviderConverterMockRecorder) ToExternalList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternalList", reflect.TypeOf((*MockSyncIdentityProviderConverter)(nil).ToExternalList), arg0)
}

// ToInternal mocks base method.
func (m *MockSyncIdentityProviderConverter) ToInternal(arg0 interface{}, arg1 *api.SyncIdentityProvider) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ToInternal", arg0, arg1)
}

// ToInternal indicates an expected call of ToInternal.
func (mr *MockSyncIdentityProviderConverterMockRecorder) ToInternal(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToInternal", reflect.TypeOf((*MockSyncIdentityProviderConverter)(nil).ToInternal), arg0, arg1)
}

// MockSecretConverter is a mock of SecretConverter interface.
type MockSecretConverter struct {
	ctrl     *gomock.Controller
	recorder *MockSecretConverterMockRecorder
}

// MockSecretConverterMockRecorder is the mock recorder for MockSecretConverter.
type MockSecretConverterMockRecorder struct {
	mock *MockSecretConverter
}

// NewMockSecretConverter creates a new mock instance.
func NewMockSecretConverter(ctrl *gomock.Controller) *MockSecretConverter {
	mock := &MockSecretConverter{ctrl: ctrl}
	mock.recorder = &MockSecretConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretConverter) EXPECT() *MockSecretConverterMockRecorder {
	return m.recorder
}

// ToExternal mocks base method.
func (m *MockSecretConverter) ToExternal(arg0 *api.Secret) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternal", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternal indicates an expected call of ToExternal.
func (mr *MockSecretConverterMockRecorder) ToExternal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternal", reflect.TypeOf((*MockSecretConverter)(nil).ToExternal), arg0)
}

// ToExternalList mocks base method.
func (m *MockSecretConverter) ToExternalList(arg0 []*api.Secret) interface{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToExternalList", arg0)
	ret0, _ := ret[0].(interface{})
	return ret0
}

// ToExternalList indicates an expected call of ToExternalList.
func (mr *MockSecretConverterMockRecorder) ToExternalList(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToExternalList", reflect.TypeOf((*MockSecretConverter)(nil).ToExternalList), arg0)
}

// ToInternal mocks base method.
func (m *MockSecretConverter) ToInternal(arg0 interface{}, arg1 *api.Secret) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ToInternal", arg0, arg1)
}

// ToInternal indicates an expected call of ToInternal.
func (mr *MockSecretConverterMockRecorder) ToInternal(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToInternal", reflect.TypeOf((*MockSecretConverter)(nil).ToInternal), arg0, arg1)
}
