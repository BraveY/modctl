/*
 *     Copyright 2024 The CNAI Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Code generated by mockery v2.53.3. DO NOT EDIT.

package modelfile

import mock "github.com/stretchr/testify/mock"

// Modelfile is an autogenerated mock type for the Modelfile type
type Modelfile struct {
	mock.Mock
}

type Modelfile_Expecter struct {
	mock *mock.Mock
}

func (_m *Modelfile) EXPECT() *Modelfile_Expecter {
	return &Modelfile_Expecter{mock: &_m.Mock}
}

// Content provides a mock function with no fields
func (_m *Modelfile) Content() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Content")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// Modelfile_Content_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Content'
type Modelfile_Content_Call struct {
	*mock.Call
}

// Content is a helper method to define mock.On call
func (_e *Modelfile_Expecter) Content() *Modelfile_Content_Call {
	return &Modelfile_Content_Call{Call: _e.mock.On("Content")}
}

func (_c *Modelfile_Content_Call) Run(run func()) *Modelfile_Content_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_Content_Call) Return(_a0 []byte) *Modelfile_Content_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_Content_Call) RunAndReturn(run func() []byte) *Modelfile_Content_Call {
	_c.Call.Return(run)
	return _c
}

// GetArch provides a mock function with no fields
func (_m *Modelfile) GetArch() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetArch")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetArch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetArch'
type Modelfile_GetArch_Call struct {
	*mock.Call
}

// GetArch is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetArch() *Modelfile_GetArch_Call {
	return &Modelfile_GetArch_Call{Call: _e.mock.On("GetArch")}
}

func (_c *Modelfile_GetArch_Call) Run(run func()) *Modelfile_GetArch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetArch_Call) Return(_a0 string) *Modelfile_GetArch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetArch_Call) RunAndReturn(run func() string) *Modelfile_GetArch_Call {
	_c.Call.Return(run)
	return _c
}

// GetCodes provides a mock function with no fields
func (_m *Modelfile) GetCodes() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetCodes")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Modelfile_GetCodes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetCodes'
type Modelfile_GetCodes_Call struct {
	*mock.Call
}

// GetCodes is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetCodes() *Modelfile_GetCodes_Call {
	return &Modelfile_GetCodes_Call{Call: _e.mock.On("GetCodes")}
}

func (_c *Modelfile_GetCodes_Call) Run(run func()) *Modelfile_GetCodes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetCodes_Call) Return(_a0 []string) *Modelfile_GetCodes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetCodes_Call) RunAndReturn(run func() []string) *Modelfile_GetCodes_Call {
	_c.Call.Return(run)
	return _c
}

// GetConfigs provides a mock function with no fields
func (_m *Modelfile) GetConfigs() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetConfigs")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Modelfile_GetConfigs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetConfigs'
type Modelfile_GetConfigs_Call struct {
	*mock.Call
}

// GetConfigs is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetConfigs() *Modelfile_GetConfigs_Call {
	return &Modelfile_GetConfigs_Call{Call: _e.mock.On("GetConfigs")}
}

func (_c *Modelfile_GetConfigs_Call) Run(run func()) *Modelfile_GetConfigs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetConfigs_Call) Return(_a0 []string) *Modelfile_GetConfigs_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetConfigs_Call) RunAndReturn(run func() []string) *Modelfile_GetConfigs_Call {
	_c.Call.Return(run)
	return _c
}

// GetDatasets provides a mock function with no fields
func (_m *Modelfile) GetDatasets() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetDatasets")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Modelfile_GetDatasets_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDatasets'
type Modelfile_GetDatasets_Call struct {
	*mock.Call
}

// GetDatasets is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetDatasets() *Modelfile_GetDatasets_Call {
	return &Modelfile_GetDatasets_Call{Call: _e.mock.On("GetDatasets")}
}

func (_c *Modelfile_GetDatasets_Call) Run(run func()) *Modelfile_GetDatasets_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetDatasets_Call) Return(_a0 []string) *Modelfile_GetDatasets_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetDatasets_Call) RunAndReturn(run func() []string) *Modelfile_GetDatasets_Call {
	_c.Call.Return(run)
	return _c
}

// GetDocs provides a mock function with no fields
func (_m *Modelfile) GetDocs() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetDocs")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Modelfile_GetDocs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDocs'
type Modelfile_GetDocs_Call struct {
	*mock.Call
}

// GetDocs is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetDocs() *Modelfile_GetDocs_Call {
	return &Modelfile_GetDocs_Call{Call: _e.mock.On("GetDocs")}
}

func (_c *Modelfile_GetDocs_Call) Run(run func()) *Modelfile_GetDocs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetDocs_Call) Return(_a0 []string) *Modelfile_GetDocs_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetDocs_Call) RunAndReturn(run func() []string) *Modelfile_GetDocs_Call {
	_c.Call.Return(run)
	return _c
}

// GetFamily provides a mock function with no fields
func (_m *Modelfile) GetFamily() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetFamily")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetFamily_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFamily'
type Modelfile_GetFamily_Call struct {
	*mock.Call
}

// GetFamily is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetFamily() *Modelfile_GetFamily_Call {
	return &Modelfile_GetFamily_Call{Call: _e.mock.On("GetFamily")}
}

func (_c *Modelfile_GetFamily_Call) Run(run func()) *Modelfile_GetFamily_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetFamily_Call) Return(_a0 string) *Modelfile_GetFamily_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetFamily_Call) RunAndReturn(run func() string) *Modelfile_GetFamily_Call {
	_c.Call.Return(run)
	return _c
}

// GetFormat provides a mock function with no fields
func (_m *Modelfile) GetFormat() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetFormat")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetFormat_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFormat'
type Modelfile_GetFormat_Call struct {
	*mock.Call
}

// GetFormat is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetFormat() *Modelfile_GetFormat_Call {
	return &Modelfile_GetFormat_Call{Call: _e.mock.On("GetFormat")}
}

func (_c *Modelfile_GetFormat_Call) Run(run func()) *Modelfile_GetFormat_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetFormat_Call) Return(_a0 string) *Modelfile_GetFormat_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetFormat_Call) RunAndReturn(run func() string) *Modelfile_GetFormat_Call {
	_c.Call.Return(run)
	return _c
}

// GetModels provides a mock function with no fields
func (_m *Modelfile) GetModels() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetModels")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// Modelfile_GetModels_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetModels'
type Modelfile_GetModels_Call struct {
	*mock.Call
}

// GetModels is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetModels() *Modelfile_GetModels_Call {
	return &Modelfile_GetModels_Call{Call: _e.mock.On("GetModels")}
}

func (_c *Modelfile_GetModels_Call) Run(run func()) *Modelfile_GetModels_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetModels_Call) Return(_a0 []string) *Modelfile_GetModels_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetModels_Call) RunAndReturn(run func() []string) *Modelfile_GetModels_Call {
	_c.Call.Return(run)
	return _c
}

// GetName provides a mock function with no fields
func (_m *Modelfile) GetName() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetName")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetName'
type Modelfile_GetName_Call struct {
	*mock.Call
}

// GetName is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetName() *Modelfile_GetName_Call {
	return &Modelfile_GetName_Call{Call: _e.mock.On("GetName")}
}

func (_c *Modelfile_GetName_Call) Run(run func()) *Modelfile_GetName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetName_Call) Return(_a0 string) *Modelfile_GetName_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetName_Call) RunAndReturn(run func() string) *Modelfile_GetName_Call {
	_c.Call.Return(run)
	return _c
}

// GetParamsize provides a mock function with no fields
func (_m *Modelfile) GetParamsize() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetParamsize")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetParamsize_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetParamsize'
type Modelfile_GetParamsize_Call struct {
	*mock.Call
}

// GetParamsize is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetParamsize() *Modelfile_GetParamsize_Call {
	return &Modelfile_GetParamsize_Call{Call: _e.mock.On("GetParamsize")}
}

func (_c *Modelfile_GetParamsize_Call) Run(run func()) *Modelfile_GetParamsize_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetParamsize_Call) Return(_a0 string) *Modelfile_GetParamsize_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetParamsize_Call) RunAndReturn(run func() string) *Modelfile_GetParamsize_Call {
	_c.Call.Return(run)
	return _c
}

// GetPrecision provides a mock function with no fields
func (_m *Modelfile) GetPrecision() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetPrecision")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetPrecision_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetPrecision'
type Modelfile_GetPrecision_Call struct {
	*mock.Call
}

// GetPrecision is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetPrecision() *Modelfile_GetPrecision_Call {
	return &Modelfile_GetPrecision_Call{Call: _e.mock.On("GetPrecision")}
}

func (_c *Modelfile_GetPrecision_Call) Run(run func()) *Modelfile_GetPrecision_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetPrecision_Call) Return(_a0 string) *Modelfile_GetPrecision_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetPrecision_Call) RunAndReturn(run func() string) *Modelfile_GetPrecision_Call {
	_c.Call.Return(run)
	return _c
}

// GetQuantization provides a mock function with no fields
func (_m *Modelfile) GetQuantization() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetQuantization")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Modelfile_GetQuantization_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetQuantization'
type Modelfile_GetQuantization_Call struct {
	*mock.Call
}

// GetQuantization is a helper method to define mock.On call
func (_e *Modelfile_Expecter) GetQuantization() *Modelfile_GetQuantization_Call {
	return &Modelfile_GetQuantization_Call{Call: _e.mock.On("GetQuantization")}
}

func (_c *Modelfile_GetQuantization_Call) Run(run func()) *Modelfile_GetQuantization_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Modelfile_GetQuantization_Call) Return(_a0 string) *Modelfile_GetQuantization_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Modelfile_GetQuantization_Call) RunAndReturn(run func() string) *Modelfile_GetQuantization_Call {
	_c.Call.Return(run)
	return _c
}

// NewModelfile creates a new instance of Modelfile. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewModelfile(t interface {
	mock.TestingT
	Cleanup(func())
}) *Modelfile {
	mock := &Modelfile{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
