/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package util

import "testing"

func TestUnseal(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal
	unsealInput := UnsealInput{
		ParentKeyPwd:      &testParentPwd,
		SecretKeyFileName: &sealOutFile,
	}
	unsealString, unsealErr := Unseal(tpmDevice, unsealInput)
	cleanup(t, tpmDevice, sealOutFile)

	if unsealErr != nil {
		t.Fatalf("unable to unseal secret data: %v", unsealErr)
	}

	if unsealString != secret {
		t.Fatalf("unsealed secret is not matched the original secret")
	}
}

func TestUnsealWithEmptySecretFileName(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	testParentPwd := ""
	emptyFileName := ""
	unsealInput := UnsealInput{
		ParentKeyPwd:      &testParentPwd,
		SecretKeyFileName: &emptyFileName,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	if unsealErr == nil {
		t.Fatal("expecting unseal error for empty scret file name")
	}
}

func TestUnsealWithNoTPM(t *testing.T) {
	testParentPwd := ""
	outFileName := "outFile"
	tpmPath := "/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	unsealInput := UnsealInput{
		ParentKeyPwd:      &testParentPwd,
		SecretKeyFileName: &outFileName,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	if unsealErr == nil {
		t.Fatal("expecting unseal error for no TPM")
	}
}

func TestUnsealReadDataError(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal with wrong output file name
	wrongOutFile := "wrongOutfile"
	unsealInput := UnsealInput{
		ParentKeyPwd:      &testParentPwd,
		SecretKeyFileName: &wrongOutFile,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	cleanup(t, tpmDevice, sealOutFile)

	if unsealErr == nil {
		t.Fatal("expecting error on reading sealed data for unseal")
	}
}

func TestUnsealReadParentHandleFileError(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal with wrong secret file path
	wrongOutFile := "/wrong/path/to/secretOutfile"
	unsealInput := UnsealInput{
		ParentKeyPwd:      &testParentPwd,
		SecretKeyFileName: &wrongOutFile,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	cleanup(t, tpmDevice, sealOutFile)

	if unsealErr == nil {
		t.Fatal("expecting error on reading parentHandle file for unseal")
	}
}

func sealData(t *testing.T, tpmDevice *TPMDevice, secret string, secretKeyFileName string) {
	// use ECC template for performance
	templateType := "ecc"
	sealInput := SealInput{
		OutputblobFile:        &secretKeyFileName,
		SecretSourceData:      &secret,
		PublicKeyTemplateType: &templateType}

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput.String())
	}
}

func cleanup(t *testing.T, tpmDevice *TPMDevice, sealFileName string) {
	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
	deleteSealFiles(sealFileName)
}
