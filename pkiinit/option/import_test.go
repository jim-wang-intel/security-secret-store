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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestImportPriorFileChange(t *testing.T) {
	var exitStatus exitCode
	var err error
	// put some test file into the current dir to trigger event
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}
	testFile := filepath.Join(curDir, "testFile")
	tearDown := setupImportTest(t)
	defer tearDown(t, testFile)

	options := PkiInitOption{
		ImportOpt: true,
	}
	importOn, _, _ := NewPkiInitOption(options)
	importOn.(*PkiInitOption).executor = testExecutor

	f := Import()

	go func() {
		exitStatus, err = f(importOn.(*PkiInitOption))
	}()

	time.Sleep(time.Second)

	testData := []byte("test data\n")
	if err := ioutil.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("cannot write testData to direcotry %s: %v", curDir, err)
	}

	assert := assert.New(t)
	assert.Equal(normal, exitStatus)
	assert.Nil(err)
}

func TestImportPostFileChange(t *testing.T) {
	var exitStatus exitCode
	var err error
	// put some test file into the current dir to trigger event
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}
	testFile := filepath.Join(curDir, "testFile")
	tearDown := setupImportTest(t)
	defer tearDown(t, testFile)

	// put some test file into the current dir to trigger event
	curDir, err = os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}

	testData := []byte("test data\n")
	if err := ioutil.WriteFile(filepath.Join(curDir, "testFile"), testData, 0644); err != nil {
		t.Fatalf("cannot write testData to direcotry %s: %v", curDir, err)
	}

	options := PkiInitOption{
		ImportOpt: true,
	}
	importOn, _, _ := NewPkiInitOption(options)
	importOn.(*PkiInitOption).executor = testExecutor

	f := Import()

	exitStatus, err = f(importOn.(*PkiInitOption))

	time.Sleep(time.Second)

	assert := assert.New(t)
	assert.Equal(normal, exitStatus)
	assert.Nil(err)
}

func TestImportOff(t *testing.T) {
	tearDown := setupImportTest(t)
	defer tearDown(t, "")

	options := PkiInitOption{
		ImportOpt: false,
	}
	importOff, _, _ := NewPkiInitOption(options)
	importOff.(*PkiInitOption).executor = testExecutor
	exitCode, err := importOff.executeOptions(Import())

	assert := assert.New(t)
	assert.Equal(normal, exitCode)
	assert.Nil(err)
}

func TestIsDirEmpty(t *testing.T) {
	assert := assert.New(t)
	_, err := isDirEmpty("/non/existing/dir/")

	assert.NotNil(err)

	// put some test file into the current dir to trigger event
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}
	empty, err := isDirEmpty(curDir)
	assert.Nil(err)
	assert.False(empty)

	// create an empty temp dir
	tempDir, err := ioutil.TempDir(curDir, "test")
	if err != nil {
		t.Fatalf("cannot create the temporary dir %s: %v", tempDir, err)
	}
	empty, err = isDirEmpty(tempDir)
	defer func() {
		// remove tempDir:
		os.RemoveAll(tempDir)
	}()

	assert.Nil(err)
	assert.True(empty)
}

func setupImportTest(t *testing.T) func(t *testing.T, testFile string) {
	testExecutor = &mockOptionsExecutor{}
	curDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get the working dir %s: %v", curDir, err)
	}

	origEnvXdgRuntimeDir := os.Getenv(envXdgRuntimeDir)
	// change it to the current working directory
	os.Setenv(envXdgRuntimeDir, curDir)

	origEnvPkiCache := os.Getenv(envPkiCache)
	// change it to the current working directory
	os.Setenv(envPkiCache, curDir)

	return func(t *testing.T, testFile string) {
		// cleanup
		os.Setenv(envXdgRuntimeDir, origEnvXdgRuntimeDir)
		os.Setenv(envPkiCache, origEnvPkiCache)
		os.Remove(testFile)
	}
}
