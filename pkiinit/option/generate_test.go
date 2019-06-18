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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testExecutor *mockOptionsExecutor
var pkisetupLocal bool
var vaultJSONPkiSetupExist bool

func TestGenerate(t *testing.T) {
	pkisetupLocal = true
	vaultJSONPkiSetupExist = true
	tearDown := setupTest(t)
	defer tearDown(t)

	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor

	f := Generate()
	exitCode, err := f(generateOn.(*PkiInitOption))

	assert := assert.New(t)
	assert.Equal(normal, exitCode)
	assert.Nil(err)
}

func TestGenerateWithPkiSetupMissing(t *testing.T) {
	pkisetupLocal = false // this will lead to pkisetup binary missing
	vaultJSONPkiSetupExist = true
	tearDown := setupTest(t)
	defer tearDown(t)
	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor

	f := Generate()
	exitCode, err := f(generateOn.(*PkiInitOption))

	assert := assert.New(t)
	assert.Equal(exitWithError, exitCode)
	assert.NotNil(err)
}

func TestGenerateWithVaultJSONPkiSetupMissing(t *testing.T) {
	pkisetupLocal = true
	vaultJSONPkiSetupExist = false // this will lead to missing json
	tearDown := setupTest(t)
	defer tearDown(t)

	generateOn := NewPkiInitOption(true)
	generateOn.(*PkiInitOption).executor = testExecutor

	f := Generate()
	exitCode, err := f(generateOn.(*PkiInitOption))

	assert := assert.New(t)
	assert.Equal(exitWithError, exitCode)
	assert.NotNil(err)
}

func TestGenerateOff(t *testing.T) {
	pkisetupLocal = true
	vaultJSONPkiSetupExist = true
	tearDown := setupTest(t)
	defer tearDown(t)

	generateOff := NewPkiInitOption(false)
	generateOff.(*PkiInitOption).executor = testExecutor
	exitCode, err := generateOff.executeOptions(Generate())

	assert := assert.New(t)
	assert.Equal(normal, exitCode)
	assert.Nil(err)
}

func setupTest(t *testing.T) func(t *testing.T) {
	testExecutor = &mockOptionsExecutor{}
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}

	pkiSetupFile := filepath.Join(curDir, pkiSetupExecutable)
	if pkisetupLocal {
		if _, err := copyFile(filepath.Join(curDir, "..", "..", "pkisetup", pkiSetupExecutable), pkiSetupFile); err != nil {
			t.Fatalf("cannot copy pkisetup binary for the test: %v", err)
		}
		os.Chmod(pkiSetupFile, 0777)
	}

	jsonVaultFile := filepath.Join(curDir, pkiSetupVaultJSON)
	if vaultJSONPkiSetupExist {
		if _, err := copyFile(filepath.Join(curDir, "..", "..", "pkisetup", pkiSetupVaultJSON), jsonVaultFile); err != nil {
			t.Fatalf("cannot copy %s for the test: %v", pkiSetupVaultJSON, err)
		}
	}

	origEnvXdgRuntimeDir := os.Getenv(envXdgRuntimeDir)
	fmt.Println("Env XDG_RUNTIME_DIR: ", origEnvXdgRuntimeDir)

	// change it to the current working directory
	os.Setenv(envXdgRuntimeDir, curDir)

	origScratchDir := pkiInitScratchDir
	testScratchDir, tempDirErr := ioutil.TempDir(curDir, "scratch")
	if tempDirErr != nil {
		t.Fatalf("cannot create temporary scratch directory for the test: %v", tempDirErr)
	}
	pkiInitScratchDir = filepath.Base(testScratchDir)

	origGeneratedDir := pkiInitGeneratedDir
	testGeneratedDir, tempDirErr := ioutil.TempDir(curDir, "generated")
	if tempDirErr != nil {
		t.Fatalf("cannot create temporary generated directory for the test: %v", tempDirErr)
	}
	pkiInitGeneratedDir = filepath.Base(testGeneratedDir)

	return func(t *testing.T) {
		// cleanup
		os.Remove(pkiSetupFile)
		os.Remove(jsonVaultFile)
		os.Setenv(envXdgRuntimeDir, origEnvXdgRuntimeDir)
		os.RemoveAll(testScratchDir)
		os.RemoveAll(testGeneratedDir)
		pkiInitScratchDir = origScratchDir
		pkiInitGeneratedDir = origGeneratedDir
		pkisetupLocal = true
		vaultJSONPkiSetupExist = true
	}
}
