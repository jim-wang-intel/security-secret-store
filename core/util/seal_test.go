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
	"log"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

var tpmDevice *TPMDevice

func TestMain(m *testing.M) {
	tpmPath := "/dev/tpm0"
	tpmDevice = NewTPMDevice(&tpmPath)
	os.Exit(m.Run())
}
func TestGetSessionList(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	emptyStr := ""

	sealInput1 := SealInput{OutputblobFile: &outFile1, SecretSourceData: &secretData1}
	sealInput2 := SealInput{OutputblobFile: &outFile2, SecretSourceData: &secretData2, PublicKeyTemplateType: &emptyStr}

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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "ecc"

	sealInput1 := SealInput{OutputblobFile: &outFile1, SecretSourceData: &secretData1, PublicKeyTemplateType: &templateType}
	sealInput2 := SealInput{OutputblobFile: &outFile2, SecretSourceData: &secretData2, PublicKeyTemplateType: &templateType}

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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "rsa"

	sealInput1 := SealInput{OutputblobFile: &outFile1, SecretSourceData: &secretData1, PublicKeyTemplateType: &templateType}
	sealInput2 := SealInput{OutputblobFile: &outFile2, SecretSourceData: &secretData2, PublicKeyTemplateType: &templateType}

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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	templateType := "unknown"

	sealInput1 := SealInput{OutputblobFile: &outFile1, SecretSourceData: &secretData1, PublicKeyTemplateType: &templateType}
	sealInput2 := SealInput{OutputblobFile: &outFile2, SecretSourceData: &secretData2, PublicKeyTemplateType: &templateType}

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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData := "SecretString"

	outFile := "outfile"

	templateType := "ecc"

	sealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: &secretData, PublicKeyTemplateType: &templateType}

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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	parentHandle := uint32(0)

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err == nil {
		t.Fatal("Expected error for parenthandle of 0")
	}
}

func TestFlushContextWrongHandle(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
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
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData := "SecretString"
	outFile := "/dev/tpm0/bad"
	templateType := "ecc"
	sealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: &secretData, PublicKeyTemplateType: &templateType}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatal("expecting error for bad seal output file path")
	}

	deleteSealFiles(outFile)
}

func TestSealNoOutputFile(t *testing.T) {
	if !tpmDevice.IsDeviceAvailable() {
		t.Skip()
	}
	secretData := "SecretString"
	outFile := ""
	sealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: &secretData}

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
	sealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: &secretData}

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
	sealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: &secretData}

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

	nullSecretSealInput := SealInput{OutputblobFile: &outFile, SecretSourceData: nil}
	if err := Seal(tpmDevice, nullSecretSealInput); err == nil {
		t.Fatal("error expected: null secret string")
	}

	nullOutputBlobFileSealInput := SealInput{OutputblobFile: nil, SecretSourceData: &secretData}
	if err := Seal(tpmDevice, nullOutputBlobFileSealInput); err == nil {
		t.Fatal("error expected: null output blob file")
	}

	deleteSealFiles(outFile)
}
