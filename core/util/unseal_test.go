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

import "testing"

func TestUnseal(t *testing.T) {
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal
	unsealInput := UnsealInput{
		parentKeyPwd:      &testParentPwd,
		secretKeyFileName: &sealOutFile,
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
	testParentPwd := ""
	emptyFileName := ""
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	unsealInput := UnsealInput{
		parentKeyPwd:      &testParentPwd,
		secretKeyFileName: &emptyFileName,
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
		parentKeyPwd:      &testParentPwd,
		secretKeyFileName: &outFileName,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	if unsealErr == nil {
		t.Fatal("expecting unseal error for no TPM")
	}
}

func TestUnsealReadDataError(t *testing.T) {
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal with wrong output file name
	wrongOutFile := "wrongOutfile"
	unsealInput := UnsealInput{
		parentKeyPwd:      &testParentPwd,
		secretKeyFileName: &wrongOutFile,
	}
	_, unsealErr := Unseal(tpmDevice, unsealInput)
	cleanup(t, tpmDevice, sealOutFile)

	if unsealErr == nil {
		t.Fatal("expecting error on reading sealed data for unseal")
	}
}

func TestUnsealReadParentHandleFileError(t *testing.T) {
	testParentPwd := ""
	secret := "SecretString"
	sealOutFile := "outfile"
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	// seal secret:
	sealData(t, tpmDevice, secret, sealOutFile)
	// then unseal with wrong secret file path
	wrongOutFile := "/wrong/path/to/secretOutfile"
	unsealInput := UnsealInput{
		parentKeyPwd:      &testParentPwd,
		secretKeyFileName: &wrongOutFile,
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
		outputblobFile:        &secretKeyFileName,
		secretSourceData:      &secret,
		publicKeyTemplateType: &templateType}

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
