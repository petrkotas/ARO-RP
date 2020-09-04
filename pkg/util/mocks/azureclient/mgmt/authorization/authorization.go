// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/Azure/ARO-RP/pkg/util/azureclient/mgmt/authorization (interfaces: PermissionsClient,RoleAssignmentsClient)

// Package mock_authorization is a generated GoMock package.
package mock_authorization

import (
	context "context"
	reflect "reflect"

	authorization "github.com/Azure/azure-sdk-for-go/services/preview/authorization/mgmt/2018-09-01-preview/authorization"
	gomock "github.com/golang/mock/gomock"
)

// MockPermissionsClient is a mock of PermissionsClient interface
type MockPermissionsClient struct {
	ctrl     *gomock.Controller
	recorder *MockPermissionsClientMockRecorder
}

// MockPermissionsClientMockRecorder is the mock recorder for MockPermissionsClient
type MockPermissionsClientMockRecorder struct {
	mock *MockPermissionsClient
}

// NewMockPermissionsClient creates a new mock instance
func NewMockPermissionsClient(ctrl *gomock.Controller) *MockPermissionsClient {
	mock := &MockPermissionsClient{ctrl: ctrl}
	mock.recorder = &MockPermissionsClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockPermissionsClient) EXPECT() *MockPermissionsClientMockRecorder {
	return m.recorder
}

// ListForResource mocks base method
func (m *MockPermissionsClient) ListForResource(arg0 context.Context, arg1, arg2, arg3, arg4, arg5 string) ([]authorization.Permission, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListForResource", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].([]authorization.Permission)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListForResource indicates an expected call of ListForResource
func (mr *MockPermissionsClientMockRecorder) ListForResource(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListForResource", reflect.TypeOf((*MockPermissionsClient)(nil).ListForResource), arg0, arg1, arg2, arg3, arg4, arg5)
}

// ListForResourceGroup mocks base method
func (m *MockPermissionsClient) ListForResourceGroup(arg0 context.Context, arg1 string) ([]authorization.Permission, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListForResourceGroup", arg0, arg1)
	ret0, _ := ret[0].([]authorization.Permission)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListForResourceGroup indicates an expected call of ListForResourceGroup
func (mr *MockPermissionsClientMockRecorder) ListForResourceGroup(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListForResourceGroup", reflect.TypeOf((*MockPermissionsClient)(nil).ListForResourceGroup), arg0, arg1)
}

// MockRoleAssignmentsClient is a mock of RoleAssignmentsClient interface
type MockRoleAssignmentsClient struct {
	ctrl     *gomock.Controller
	recorder *MockRoleAssignmentsClientMockRecorder
}

// MockRoleAssignmentsClientMockRecorder is the mock recorder for MockRoleAssignmentsClient
type MockRoleAssignmentsClientMockRecorder struct {
	mock *MockRoleAssignmentsClient
}

// NewMockRoleAssignmentsClient creates a new mock instance
func NewMockRoleAssignmentsClient(ctrl *gomock.Controller) *MockRoleAssignmentsClient {
	mock := &MockRoleAssignmentsClient{ctrl: ctrl}
	mock.recorder = &MockRoleAssignmentsClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRoleAssignmentsClient) EXPECT() *MockRoleAssignmentsClientMockRecorder {
	return m.recorder
}

// Create mocks base method
func (m *MockRoleAssignmentsClient) Create(arg0 context.Context, arg1, arg2 string, arg3 authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create
func (mr *MockRoleAssignmentsClientMockRecorder) Create(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRoleAssignmentsClient)(nil).Create), arg0, arg1, arg2, arg3)
}

// DeleteByID mocks base method
func (m *MockRoleAssignmentsClient) DeleteByID(arg0 context.Context, arg1 string) (authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeleteByID indicates an expected call of DeleteByID
func (mr *MockRoleAssignmentsClientMockRecorder) DeleteByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockRoleAssignmentsClient)(nil).DeleteByID), arg0, arg1)
}

// List mocks base method
func (m *MockRoleAssignmentsClient) List(arg0 context.Context, arg1 string) ([]authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].([]authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List
func (mr *MockRoleAssignmentsClientMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRoleAssignmentsClient)(nil).List), arg0, arg1)
}

// ListForScope mocks base method
func (m *MockRoleAssignmentsClient) ListForScope(arg0 context.Context, arg1, arg2 string) ([]authorization.RoleAssignment, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListForScope", arg0, arg1, arg2)
	ret0, _ := ret[0].([]authorization.RoleAssignment)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListForScope indicates an expected call of ListForScope
func (mr *MockRoleAssignmentsClientMockRecorder) ListForScope(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListForScope", reflect.TypeOf((*MockRoleAssignmentsClient)(nil).ListForScope), arg0, arg1, arg2)
}
