/*
 * Copyright (C) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package util

import (
	"errors"
	"log"
	"os"
	"path"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// FlushContext executes the FlushContext subcommands to clear TPM memory for a given handle
func FlushContext(tpmDev *TPMDevice, handle *uint32) error {
	if *handle == 0 {
		return errors.New("No handle given")
	}

	rw, err := tpmDev.OpenTPMDevice()
	if err != nil {
		return err
	}
	defer rw.Close()

	tpmHandle := tpmutil.Handle(*handle)
	if flushErr := tpm2.FlushContext(rw, tpmHandle); flushErr != nil {
		return flushErr
	}

	log.Printf("TPM handle 0x%x has flushed successfully\n", tpmHandle) // info

	dir, err := os.Getwd()
	if err != nil {
		log.Printf("unable to get working directory for parent handle %s: %v\n", parentHandleFileName, err) // warning
	}
	parentHandleFilePath := path.Join(dir, parentHandleFileName)

	if _, statErr := os.Stat(parentHandleFileName); statErr == nil {
		if delErr := os.Remove(parentHandleFilePath); delErr != nil {
			log.Printf("unable to delete parent handle file %s: %v\n", parentHandleFilePath, delErr) // warning
		}
	} else if os.IsNotExist(statErr) {
		log.Printf("parent handle file [%s] does not exist\n", parentHandleFilePath) // info
	}
	return nil
}
