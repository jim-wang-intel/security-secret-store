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
	"log"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestGetSessionList(t *testing.T) {
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	rw, err := tpmDevice.OpenTPMDevice()
	if err != nil {
		t.Fatal("cannot open TPM device")
	}
	defer rw.Close()
	if psl, _, capErr := tpm2.GetCapability(rw, tpm2.CapabilityHandles, 1, uint32(tpm2.HandleTypeLoadedSession)<<24); capErr != nil {
		t.Fatalf("unable to get capability: %v", capErr)
	} else {
		log.Printf("psl %v", psl)
		for _, capVal := range psl {
			log.Printf("capability type: %v  capability val: 0x%x", reflect.TypeOf(capVal), capVal)
		}
	}
}

func TestSealWithNoTemplate(t *testing.T) {
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	emptyStr := ""

	sealInput1 := SealInput{outputblobFile: &outFile1, secretSourceData: &secretData1}
	sealInput2 := SealInput{outputblobFile: &outFile2, secretSourceData: &secretData2, publicKeyTemplateType: &emptyStr}

	if len(sealInput1.String()) == 0 {
		t.Fatal("expecting some non-empty output string from seal input")
	}

	log.Printf("sealInput1: %s, sealInput2: %s", sealInput1.String(), sealInput2.String())

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput1); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput1.String())
	}

	// Now parent handle exists, should still work
	if err := Seal(tpmDevice, sealInput2); err != nil {
		t.Fatalf("Encountered error for second TPM seal %v, with input: %v", err, sealInput2.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	deleteSealFiles(outFile1)
	deleteSealFiles(outFile2)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
}

func TestSealWithECCTemplate(t *testing.T) {
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "ecc"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	sealInput1 := SealInput{outputblobFile: &outFile1, secretSourceData: &secretData1, publicKeyTemplateType: &templateType}
	sealInput2 := SealInput{outputblobFile: &outFile2, secretSourceData: &secretData2, publicKeyTemplateType: &templateType}

	log.Printf("sealInput1: %s, sealInput2: %s", sealInput1.String(), sealInput2.String())

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput1); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput1.String())
	}

	// Now parent handle exists, should still work
	if err := Seal(tpmDevice, sealInput2); err != nil {
		t.Fatalf("Encountered error for second TPM seal %v, with input: %v", err, sealInput2.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	deleteSealFiles(outFile1)
	deleteSealFiles(outFile2)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
}

func TestSealWithRSATemplate(t *testing.T) {
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "rsa"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	sealInput1 := SealInput{outputblobFile: &outFile1, secretSourceData: &secretData1, publicKeyTemplateType: &templateType}
	sealInput2 := SealInput{outputblobFile: &outFile2, secretSourceData: &secretData2, publicKeyTemplateType: &templateType}

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput1); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput1.String())
	}

	// Now parent handle exists, should still work
	if err := Seal(tpmDevice, sealInput2); err != nil {
		t.Fatalf("Encountered error for second TPM seal %v, with input: %v", err, sealInput2.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	deleteSealFiles(outFile1)
	deleteSealFiles(outFile2)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
}

func TestSealWithUnknownTemplate(t *testing.T) {
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "unknown"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	sealInput1 := SealInput{outputblobFile: &outFile1, secretSourceData: &secretData1, publicKeyTemplateType: &templateType}
	sealInput2 := SealInput{outputblobFile: &outFile2, secretSourceData: &secretData2, publicKeyTemplateType: &templateType}

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput1); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput1.String())
	}

	// Now parent handle exists, should still work
	if err := Seal(tpmDevice, sealInput2); err != nil {
		t.Fatalf("Encountered error for second TPM seal %v, with input: %v", err, sealInput2.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	deleteSealFiles(outFile1)
	deleteSealFiles(outFile2)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
}

func TestFlushContextNoParentHandleFile(t *testing.T) {
	secretData := "SecretString"

	outFile := "outfile"

	templateType := "ecc"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData, publicKeyTemplateType: &templateType}

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	deleteSealFiles(outFile)

	// now before call FlushContext, we intentionally delete the parent handle file to
	// simulate the parentHandle file not existing
	dir, err := os.Getwd()
	if err != nil {
		log.Printf("unable to get working directory for parent handle %s: %v\n", parentHandleFileName, err) // warning
	}
	parentHandleFilePath := path.Join(dir, parentHandleFileName)
	os.Remove(parentHandleFilePath)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}
}

func TestGetDefaultSRKTemplate(t *testing.T) {
	var unknownTemplateTypeInt uint
	unknownTemplateTypeInt = 99
	unknownTemplateType := TemplateType(unknownTemplateTypeInt)
	publicTemplate := GetSRKTemplate(unknownTemplateType)
	if publicTemplate.Type != tpm2.AlgRSA {
		t.Fatalf("expecting to get RSA template for unknown template type %d", unknownTemplateTypeInt)
	}
}

func TestFlushContextNoHandle(t *testing.T) {
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	parentHandle := uint32(0)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err == nil {
		t.Fatal("Expected error for parenthandle of 0")
	}
}

func TestFlushContextWrongHandle(t *testing.T) {

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	parentHandle := uint32(12345)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err == nil {
		t.Fatal("Expected error for parenthandle of 0")
	}
}

func TestFlushContextNoTPM(t *testing.T) {

	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err == nil {
		t.Fatal("Expected error for wrong TPM path")
	}
}

func TestSealBadSealOutFilePath(t *testing.T) {
	secretData := "SecretString"
	outFile := "/dev/tpm0/bad"
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	templateType := "ecc"
	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData, publicKeyTemplateType: &templateType}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatal("expecting error for bad seal output file path")
	}

	deleteSealFiles(outFile)
}

func TestSealNoOutputFile(t *testing.T) {
	secretData := "SecretString"
	outFile := ""
	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)
	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatalf("error expected: empty output file %v", err)
	}

	deleteSealFiles(outFile)
}

func TestSealNoTPM(t *testing.T) {
	secretData := "SecretString"
	outFile := "outFile"
	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatalf("error expected: empty outfile %v", err)
	}

	deleteSealFiles(outFile)
}

func TestSealNoSecretData(t *testing.T) {
	secretData := ""
	outFile := "outfile"
	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatalf("error expected: empty secret string %v", err)
	}

	deleteSealFiles(outFile)
}

func TestSealNullInputs(t *testing.T) {
	secretData := "secret"
	outFile := "outfile"
	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)

	nullSecretSealInput := SealInput{outputblobFile: &outFile, secretSourceData: nil}
	if err := Seal(tpmDevice, nullSecretSealInput); err == nil {
		t.Fatal("error expected: null secret string")
	}

	nullOutputBlobFileSealInput := SealInput{outputblobFile: nil, secretSourceData: &secretData}
	if err := Seal(tpmDevice, nullOutputBlobFileSealInput); err == nil {
		t.Fatal("error expected: null output blob file")
	}

	deleteSealFiles(outFile)
}
