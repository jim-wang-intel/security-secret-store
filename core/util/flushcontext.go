/*
 * Copyright (C) 2019 Intel Corporation
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
