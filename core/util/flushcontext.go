/*
 * INTEL CONFIDENTIAL
 * Copyright (2018-2019) Intel Corporation.
 *
 * The source code contained or described herein and all documents related to the source code ("Material")
 * are owned by Intel Corporation or its suppliers or licensors. Title to the Material remains with
 * Intel Corporation or its suppliers and licensors. The Material may contain trade secrets and proprietary
 * and confidential information of Intel Corporation and its suppliers and licensors, and is protected by
 * worldwide copyright and trade secret laws and treaty provisions. No part of the Material may be used,
 * copied, reproduced, modified, published, uploaded, posted, transmitted, distributed, or disclosed in
 * any way without Intel/'s prior express written permission.
 * No license under any patent, copyright, trade secret or other intellectual property right is granted
 * to or conferred upon you by disclosure or delivery of the Materials, either expressly, by implication,
 * inducement, estoppel or otherwise. Any license under such intellectual property rights must be express
 * and approved by Intel in writing.
 * Unless otherwise agreed by Intel in writing, you may not remove or alter this notice or any other
 * notice embedded in Materials by Intel or Intel's suppliers or licensors in any way.
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
