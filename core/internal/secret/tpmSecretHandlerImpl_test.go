/*
 * Copyright (C) 2019 Intel Corporation
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
