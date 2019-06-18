//
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.
//
// SPDX-License-Identifier: Apache-2.0'
//
package option

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

func TestNewPkiInitOption(t *testing.T) {
	assert := assert.New(t)
	// generate option given
	generateOn := NewPkiInitOption(true)
	assert.NotNil(generateOn)
	assert.Equal(true, generateOn.(*PkiInitOption).generateOpt)
	// generate option omitted
	generateOff := NewPkiInitOption(false)
	assert.NotNil(generateOff)
	assert.Equal(false, generateOff.(*PkiInitOption).generateOpt)
}

func TestProcessOptionNormal(t *testing.T) {
	testExecutor := &mockOptionsExecutor{}
	// normal case
	testExecutor.On("executeOptions", mock.AnythingOfTypeArgument(
		"func(*option.PkiInitOption) (option.exitCode, error)")).
		Return(normal, nil).Once()

	assert := assert.New(t)

	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor
	exitCode, err := generateOn.ProcessOptions()
	assert.Equal(normal.intValue(), exitCode)
	assert.Nil(err)

	testExecutor.AssertExpectations(t)
}

func TestProcessOptionError(t *testing.T) {
	testExecutor := &mockOptionsExecutor{}
	generateErr := errors.New("failed to execute generate")
	// error case
	testExecutor.On("executeOptions", mock.AnythingOfTypeArgument(
		"func(*option.PkiInitOption) (option.exitCode, error)")).
		Return(exitWithError, generateErr).Once()

	assert := assert.New(t)

	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor
	exitCode, err := generateOn.ProcessOptions()
	assert.Equal(exitWithError.intValue(), exitCode)
	assert.Equal(generateErr, err)

	testExecutor.AssertExpectations(t)
}

func TestExecuteOption(t *testing.T) {
	testExecutor := &mockOptionsExecutor{}
	assert := assert.New(t)

	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor
	exitCode, err := generateOn.executeOptions(mockGenerate())
	assert.Equal(normal, exitCode)
	assert.Nil(err)

	generateOff := NewPkiInitOption(false)
	generateOff.(*PkiInitOption).executor = testExecutor
	exitCode, err = generateOff.executeOptions(mockGenerate())
	assert.Equal(normal, exitCode)
	assert.Nil(err)
}

func mockGenerate() func(*PkiInitOption) (exitCode, error) {
	return func(pkiInitOpton *PkiInitOption) (exitCode, error) {
		return normal, nil
	}
}
