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
	"os"
	"testing"

	"github.com/edgexfoundry/security-secret-store/core/util"
	"github.com/hashicorp/vault/api"
)

func TestMain(m *testing.M) {
	tpmPath := "/dev/tpm0"
	tpmDevice = util.NewTPMDevice(&tpmPath)
	os.Exit(m.Run())
}
func TestTPMSealVaultSecrets(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}

	mockVaultSecrets := api.InitResponse{
		Keys:      []string{"tpm1", "tpm2"},
		KeysB64:   []string{"tpm1", "tpm2"},
		RootToken: "tpm1",
	}
	mockVaultSecretsBytes, _ := json.Marshal(mockVaultSecrets)
	mockSealOutputFile := "vaultmock"
	mockTPMText := TPM{}
	sealErr := mockTPMText.SealVaultSecrets(mockVaultSecretsBytes, mockSealOutputFile)
	if sealErr != nil {
		t.Fatal()
	}
}

func TestTPMUnSealVaultSecrets(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	//Seal first to test unseal
	mockSealOutputFile := "vaultmock"
	mockTPMText := TPM{}
	mockVaultSecrets := api.InitResponse{
		Keys:      []string{"tpm1", "tpm2"},
		KeysB64:   []string{"tpm1", "tpm2"},
		RootToken: "tpm1",
	}
	mockVaultSecretsBytes, _ := json.Marshal(mockVaultSecrets)
	sealErr := mockTPMText.SealVaultSecrets(mockVaultSecretsBytes, mockSealOutputFile)
	if sealErr != nil {
		t.Fatal()
	}
	//Unseal
	unSealedBytes, unSealErr := mockTPMText.UnsealVaultSecrets(mockSealOutputFile)
	if unSealErr != nil {
		t.Fatal()
	}

	if len(unSealedBytes) == 0 {
		t.Fatal("retruned unsealed bytes were empty")
	}

}
