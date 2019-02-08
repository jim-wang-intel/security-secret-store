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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// UnsealInput contains inputs to do TPM2 unseal subcommand
// which loads both the private and public portions of an object into the TPM device
// and then do the unseal without session handle
type UnsealInput struct {
	// ParentKeyPwd is the parent key password from seal
	ParentKeyPwd *string
	// SecretKeyFileName is the secret key file name for both public and private keys
	SecretKeyFileName *string
}

// Unseal executes the Unseal subcommands
func Unseal(tpmDev *TPMDevice, unsealInput UnsealInput) (unsealedData string, unsealErr error) {
	log.Printf("secretKeyFileName: %s\n", *unsealInput.SecretKeyFileName)

	secretKeyFilename := strings.TrimSpace(*unsealInput.SecretKeyFileName)

	if len(secretKeyFilename) == 0 {
		return "", errors.New("secret key file path cannot be empty")
	}

	rw, err := tpmDev.OpenTPMDevice()
	if err != nil {
		return "", err
	}
	defer rw.Close()

	// read the parent handle from file if any
	parentHdl := readParentHandle(secretKeyFilename)

	log.Printf("Loading an object into TPM device with parent handle 0x%x and key file name %s\n", parentHdl, secretKeyFilename)

	if sealPrivate, sealPublic, readErr := readSealedData(secretKeyFilename); readErr != nil {
		return "", readErr
	} else {
		objHandle, _, loadErr := tpm2.Load(rw, parentHdl, *unsealInput.ParentKeyPwd, sealPublic, sealPrivate)
		if loadErr != nil {
			log.Printf("parentHandle 0x%x sealPrivate: %v sealPublic: %v\n", parentHdl, sealPrivate, sealPublic)
			log.Printf("unable to load data into TPM: %v\n", loadErr)
			return "", loadErr
		}
		defer func() {
			if flushErr := tpm2.FlushContext(rw, objHandle); flushErr != nil {
				log.Printf("unable to flush object handle 0x%x: %v\n", objHandle, flushErr)
			}
		}()
		log.Printf("Successfully loaded sealed data into TPM with parent handle: 0x%x, and got the object handle: 0x%x\n", parentHdl, objHandle)

		objectPwd := "test"
		pcr := 0
		unsealedBytes, unsealErr := unsealData(rw, objHandle, pcr, objectPwd)
		if unsealErr != nil {
			return "", unsealErr
		}
		unsealedData = string(unsealedBytes[:])
	}

	log.Println("Unseal data with TPM device successfully done.")
	return unsealedData, nil
}

func unsealData(rw io.ReadWriter, objHandle tpmutil.Handle, pcr int, objectPwd string) (data []byte, retErr error) {
	sessionHandle, policy, sessionPolicyGetErr := GetSimpleSessionPolicyWithPCR(rw, pcr)
	defer func() {
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		log.Printf("sessionHandle 0x%x has been flushed\n", sessionHandle)
	}()

	if sessionPolicyGetErr != nil {
		return nil, sessionPolicyGetErr
	}

	log.Printf("Got policy %v\n", policy)

	unsealedData, err := tpm2.UnsealWithSession(rw, sessionHandle, objHandle, objectPwd)

	if err != nil {
		return nil, fmt.Errorf("unable to unseal data: %v", err)
	}

	return unsealedData, nil
}

func readParentHandle(secretKeyFilename string) (parentHandle tpmutil.Handle) {
	parentHandleFileName := GetTPMParentHandleFileName(secretKeyFilename)
	if _, err := os.Stat(parentHandleFileName); err == nil {
		// parent handle already exists, retrieve and reuse it
		parentHandle = RetrieveParentHandle(parentHandleFileName)
	} else if os.IsNotExist(err) {
		log.Printf("unable to find the parent handle file %s", parentHandleFileName)
	} else {
		log.Printf("error on os stat parent handle: %v", err)
	}
	return parentHandle
}

func readSealedData(blobFilePath string) (sealPrivate []byte, sealPublic []byte, readErr error) {
	privateKeyFile := blobFilePath + ".prv"
	publicKeyFile := blobFilePath + ".pub"

	if sealPrivate, readErr = ioutil.ReadFile(privateKeyFile); readErr != nil {
		return nil, nil, readErr
	}

	if sealPublic, readErr = ioutil.ReadFile(publicKeyFile); readErr != nil {
		return nil, nil, readErr
	}

	return sealPrivate, sealPublic, nil
}
