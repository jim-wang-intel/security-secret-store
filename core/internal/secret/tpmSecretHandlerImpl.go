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

package secret

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/edgexfoundry/security-secret-store/core/util"
)

var tpmDevice *util.TPMDevice

type TPM struct{}

const (
	vaultKeysSealFileSuffix       = "_keys"
	vaultKeysBase64SealFileSuffix = "_keysbase64"
	vaultRootTokenSealFileSuffix  = "_roottoken"
	vauleKeyStringSeparator       = ","
)

// SealVaultSecrets seals the secret data with TPM device
func (t TPM) SealVaultSecrets(secretDataBytes []byte, encryptedOutputFile string) error {
	// cleanup the left-over sealed file under the same directory of encryptedOutputFile
	// before we do a new seal
	cleanup(encryptedOutputFile)

	// use ECC as public key template type for its much better performance on creating primary keys
	templateType := "ecc"
	//secretData := string(secretDataBytes)
	//fmt.Printf("secreteData string: %s\n", secretData)

	// due to the restriciton of TPM, the secretData in JSON is split
	// into small chunck like each field per sealInput
	// for example: "keys" is one sealed blob output
	// "root-token" is antoher blob oupput
	var vaultSecrets api.InitResponse
	if unmarshalErr := json.Unmarshal(secretDataBytes, &vaultSecrets); unmarshalErr != nil {
		return unmarshalErr
	}
	keysSealOutFile := encryptedOutputFile + vaultKeysSealFileSuffix

	vaultKeys := strings.Join(vaultSecrets.Keys[:], vauleKeyStringSeparator)
	keysSealInput := util.SealInput{
		OutputblobFile:        &keysSealOutFile,
		SecretSourceData:      &vaultKeys,
		PublicKeyTemplateType: &templateType,
	}
	log.Printf("keysSealInput: %s", keysSealInput.String())

	if err := util.Seal(getTPMDevice(), keysSealInput); err != nil {
		return fmt.Errorf("Encountered error for TPM seal vault keys: %v, with input: %v", err, keysSealInput.String())
	}

	keysBase64SealOutFile := encryptedOutputFile + vaultKeysBase64SealFileSuffix
	vaultKeysBase64 := strings.Join(vaultSecrets.KeysB64[:], vauleKeyStringSeparator)
	keysBase64SealInput := util.SealInput{
		OutputblobFile:        &keysBase64SealOutFile,
		SecretSourceData:      &vaultKeysBase64,
		PublicKeyTemplateType: &templateType,
	}

	log.Printf("keysBase64SealInput: %s", keysBase64SealInput.String())

	if err := util.Seal(getTPMDevice(), keysBase64SealInput); err != nil {
		return fmt.Errorf("Encountered error for TPM seal vault keys base 64: %v, with input: %v", err, keysBase64SealInput.String())
	}

	rootTokenSealOutFile := encryptedOutputFile + vaultRootTokenSealFileSuffix
	rootTokenSealInput := util.SealInput{
		OutputblobFile:        &rootTokenSealOutFile,
		SecretSourceData:      &vaultSecrets.RootToken,
		PublicKeyTemplateType: &templateType,
	}

	log.Printf("rootTokenSealInput: %s", rootTokenSealInput.String())

	if err := util.Seal(getTPMDevice(), rootTokenSealInput); err != nil {
		return fmt.Errorf("Encountered error for TPM seal vault root token: %v, with input: %v", err, rootTokenSealInput.String())
	}

	return nil
}

// UnsealVaultSecrets unlocks the secret data with TPM device
func (t TPM) UnsealVaultSecrets(vaultSecretFile string) ([]byte, error) {
	// due to the restriciton of TPM, the secretData in JSON is split
	// into small chunck like each field per sealInput
	// so unsealInput also has the similar way to each field
	vaultKeysFile := vaultSecretFile + vaultKeysSealFileSuffix
	vaultKeysUnsealInput := util.UnsealInput{
		SecretKeyFileName: &vaultKeysFile,
	}

	vaultKeyStr, unsealErr := util.Unseal(getTPMDevice(), vaultKeysUnsealInput)
	if unsealErr != nil {
		return nil, unsealErr
	}
	// reconstruct the keys field value back to the slice of key strings
	vaultKeys := strings.Split(vaultKeyStr, vauleKeyStringSeparator)

	vaultKeysBase64File := vaultSecretFile + vaultKeysBase64SealFileSuffix
	vaultKeysBase64UnsealInput := util.UnsealInput{
		SecretKeyFileName: &vaultKeysBase64File,
	}

	vaultKeyBase64Str, unsealErr := util.Unseal(getTPMDevice(), vaultKeysBase64UnsealInput)
	if unsealErr != nil {
		return nil, unsealErr
	}
	// reconstruct the keys field value back to the slice of key strings
	vaultKeysBase64 := strings.Split(vaultKeyBase64Str, vauleKeyStringSeparator)

	vaultRootTokenFile := vaultSecretFile + vaultRootTokenSealFileSuffix
	vaultRootTokenUnsealInput := util.UnsealInput{
		SecretKeyFileName: &vaultRootTokenFile,
	}

	vaultRootToken, unsealErr := util.Unseal(getTPMDevice(), vaultRootTokenUnsealInput)
	if unsealErr != nil {
		return nil, unsealErr
	}

	vaultSecrets := api.InitResponse{
		Keys:      vaultKeys,
		KeysB64:   vaultKeysBase64,
		RootToken: vaultRootToken,
	}

	vaultSecretBytes, _ := json.Marshal(vaultSecrets)

	return vaultSecretBytes, nil
}

func getTPMDevice() *util.TPMDevice {
	if tpmDevice == nil {
		// by default the hardware TPM will create this device
		tpmPath := "/dev/tpm0"
		tpmDevice = util.NewTPMDevice(&tpmPath)
	}
	return tpmDevice
}

func cleanup(file string) {
	parentHandleFileName := util.GetTPMParentHandleFileName(file)
	if _, err := os.Stat(parentHandleFileName); err == nil {
		// parent handle exists, cleans it up
		parentHandle := uint32(util.RetrieveParentHandle(parentHandleFileName))
		// flush the TPM parentHandle context if any
		if flushErr := util.FlushContext(getTPMDevice(), &parentHandle); flushErr != nil {
			log.Printf("cannot flush TPM context for parentHandle: 0x%x", parentHandle)
		}
		// clean up the parentHandle file:
		os.Remove(parentHandleFileName)
	}

	// clean up the secret blob files:
	dir, _ := os.Getwd()
	cleanupSealedFiles(dir)
}

func cleanupSealedFiles(pathToCleanup string) {
	filepath.Walk(pathToCleanup, deletePrvFiles)
	filepath.Walk(pathToCleanup, deletePubFiles)
}

func deletePrvFiles(path string, fileInfo os.FileInfo, err error) (e error) {
	if strings.HasSuffix(fileInfo.Name(), ".prv") {
		os.Remove(path)
	}
	return
}

func deletePubFiles(path string, fileInfo os.FileInfo, err error) (e error) {
	if strings.HasSuffix(fileInfo.Name(), ".pub") {
		os.Remove(path)
	}
	return
}
