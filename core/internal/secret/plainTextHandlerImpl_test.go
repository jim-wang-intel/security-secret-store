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
	"strings"
	"testing"
)

func TestSealVaultSecrets(t *testing.T) {

	mockVaultSecret := "mock"
	mockVaultSecretsBytes, _ := json.Marshal(mockVaultSecret)
	mockSealOutputFile := "vaultmock"
	mockPlainText := PlainText{}
	os.Remove(mockSealOutputFile)
	sealErr := mockPlainText.SealVaultSecrets(mockVaultSecretsBytes, mockSealOutputFile)
	if sealErr != nil {
		t.Fatal()
	}
	if !checkFileExists(mockSealOutputFile) {
		t.Fatal()
	}
}

func TestUnSealVaultSecrets(t *testing.T) {
	mockSealOutputFile := "vaultmock"
	os.Remove(mockSealOutputFile)
	mockVaultSecret := "mock"
	mockVaultSecretsBytes := []byte(mockVaultSecret)
	mockPlainText := PlainText{}

	sealErr := mockPlainText.SealVaultSecrets(mockVaultSecretsBytes, mockSealOutputFile)
	if sealErr == nil {
		if unSealedBytes, err := mockPlainText.UnsealVaultSecrets(mockSealOutputFile); err != nil {
			t.Fatal()
		} else {
			if strings.Compare(string(unSealedBytes), mockVaultSecret) != 0 {
				t.Fatal("unsealed bytes are not equal")
			}
		}
	}

}

func checkFileExists(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}
