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
	// nil pointer check
	if unsealInput.SecretKeyFileName == nil {
		return "", errors.New("secret key file path cannot be empty")
	}

	log.Printf("secretKeyFileName: %s\n", *unsealInput.SecretKeyFileName)

	secretKeyFilename := strings.TrimSpace(*unsealInput.SecretKeyFileName)

	if len(secretKeyFilename) == 0 {
		return "", errors.New("secret key file path cannot be empty")
	}

	var parentPwd string
	if unsealInput.ParentKeyPwd != nil {
		parentPwd = *unsealInput.ParentKeyPwd
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
		objHandle, _, loadErr := tpm2.Load(rw, parentHdl, parentPwd, sealPublic, sealPrivate)
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

		objectPwd := emptyPassword
		unsealedBytes, unsealErr := unsealData(rw, objHandle, objectPwd)
		if unsealErr != nil {
			return "", unsealErr
		}
		unsealedData = string(unsealedBytes[:])
	}

	log.Println("Unseal data with TPM device successfully done.")
	return unsealedData, nil
}

func unsealData(rw io.ReadWriter, objHandle tpmutil.Handle, objectPwd string) (data []byte, retErr error) {
	sessionHandle, policy, sessionPolicyGetErr := GetSimpleSessionPolicyWithPCR(rw)
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
	parentHndlFileName := GetTPMParentHandleFileName(secretKeyFilename)
	if _, err := os.Stat(parentHndlFileName); err == nil {
		// parent handle already exists, retrieve and reuse it
		parentHandle = RetrieveParentHandle(parentHndlFileName)
	} else if os.IsNotExist(err) {
		log.Printf("unable to find the parent handle file %s", parentHndlFileName)
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
