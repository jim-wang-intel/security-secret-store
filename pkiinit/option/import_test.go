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
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImport(t *testing.T) {
	tearDown := setupImportTest(t)
	defer tearDown(t)

	options := PkiInitOption{
		ImportOpt: true,
	}
	importOn, _, _ := NewPkiInitOption(options)
	importOn.(*PkiInitOption).executor = testExecutor

	f := Import()
	exitCode, err := f(importOn.(*PkiInitOption))

	assert := assert.New(t)
	assert.Equal(normal, exitCode)
	assert.Nil(err)
}

// func TestGenerateWithPkiSetupMissing(t *testing.T) {
// 	pkisetupLocal = false // this will lead to pkisetup binary missing
// 	vaultJSONPkiSetupExist = true
// 	tearDown := setupImportTest(t)
// 	defer tearDown(t)

// 	options := PkiInitOption{
// 		GenerateOpt: true,
// 	}
// 	generateOn, _, _ := NewPkiInitOption(options)
// 	generateOn.(*PkiInitOption).executor = testExecutor

// 	f := Generate()
// 	exitCode, err := f(generateOn.(*PkiInitOption))

// 	assert := assert.New(t)
// 	assert.Equal(exitWithError, exitCode)
// 	assert.NotNil(err)
// }

// func TestGenerateWithVaultJSONPkiSetupMissing(t *testing.T) {
// 	pkisetupLocal = true
// 	vaultJSONPkiSetupExist = false // this will lead to missing json
// 	tearDown := setupImportTest(t)
// 	defer tearDown(t)

// 	options := PkiInitOption{
// 		GenerateOpt: true,
// 	}
// 	generateOn, _, _ := NewPkiInitOption(options)
// 	generateOn.(*PkiInitOption).executor = testExecutor

// 	f := Generate()
// 	exitCode, err := f(generateOn.(*PkiInitOption))

// 	assert := assert.New(t)
// 	assert.Equal(exitWithError, exitCode)
// 	assert.NotNil(err)
// }

// func TestGenerateOff(t *testing.T) {
// 	pkisetupLocal = true
// 	vaultJSONPkiSetupExist = true
// 	tearDown := setupImportTest(t)
// 	defer tearDown(t)

// 	options := PkiInitOption{
// 		GenerateOpt: false,
// 	}
// 	generateOff, _, _ := NewPkiInitOption(options)
// 	generateOff.(*PkiInitOption).executor = testExecutor
// 	exitCode, err := generateOff.executeOptions(Generate())

// 	assert := assert.New(t)
// 	assert.Equal(normal, exitCode)
// 	assert.Nil(err)
// }

func setupImportTest(t *testing.T) func(t *testing.T) {
	testExecutor = &mockOptionsExecutor{}
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}

	origEnvXdgRuntimeDir := os.Getenv(envXdgRuntimeDir)
	fmt.Println("Env XDG_RUNTIME_DIR: ", origEnvXdgRuntimeDir)

	// change it to the current working directory
	os.Setenv(envXdgRuntimeDir, curDir)

	return func(t *testing.T) {
		// cleanup
		os.Setenv(envXdgRuntimeDir, origEnvXdgRuntimeDir)
	}
}
