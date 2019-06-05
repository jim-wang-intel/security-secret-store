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
	"flag"
	"fmt"
	"os"
)

type exit interface {
	callExit(int)
}

type exitCode struct {
	exit
}

var exitInstance = newExit(&exitCode{})

func main() {
	var helpOpt bool
	// only help option for this phase
	if flag.Lookup("h") == nil {
		// only register once if it is empty
		// to prevent "redefined flag error"
		flag.BoolVar(&helpOpt, "h", false, "help message")
		flag.BoolVar(&helpOpt, "help", false, "help message")
	}

	flag.Parse()

	var statusCode int
	if helpOpt {
		// as specified in the requirement, help option terminates with 0 exit status
		flag.Usage()
		statusCode = 0
	} else {
		if len(os.Args) < 2 {
			fmt.Println("Please specify option for pki-init.")
			flag.Usage()
			statusCode = 1
		}
	}

	exitInstance.callExit(statusCode)
}

func newExit(exit exit) exit {
	return &exitCode{exit: exit}
}

func (code *exitCode) callExit(statusCode int) {
	os.Exit(statusCode)
}
