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
package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHelpOption(t *testing.T) {
	exitInstance = newTestExit(&testExitCode{})
	runWithHelpOption()
	assert.Equal(t, 0, (exitInstance.(*testExitCode)).getStatusCode())
}

func TestNoOption(t *testing.T) {
	exitInstance = newTestExit(&testExitCode{})
	runWithNoOption()
	assert.Equal(t, 1, (exitInstance.(*testExitCode)).getStatusCode())
}

func runWithNoOption() {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// case 1: no option given
	os.Args = []string{"cmd"}
	main()
}

func runWithHelpOption() {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// case 2: h or help option given
	os.Args = []string{"cmd", "-help"}
	main()
}

type testExitCode struct {
	exitCode
	testStatusCode int
}

func (testExit *testExitCode) callExit(statusCode int) {
	fmt.Printf("In test: exitCode = %d\n", statusCode)
	testExit.testStatusCode = statusCode
}

func (testExit *testExitCode) getStatusCode() int {
	return testExit.testStatusCode
}

func newTestExit(exit exit) exit {
	return &testExitCode{}
}
