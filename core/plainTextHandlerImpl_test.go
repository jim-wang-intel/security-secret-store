package main

import (
	"encoding/json"
	"fmt"
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
			fmt.Println(string(unSealedBytes))
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
