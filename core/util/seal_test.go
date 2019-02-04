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

func TestSealWithFlushContext(t *testing.T) {

	secretData1 := "SecretString1"
	secretData2 := "SecretString2"

	outFile1 := "outfile1"
	outFile2 := "outfile2"

	tpmPath := "/dev/tpm0"
	tpmDevice := NewTPMDevice(&tpmPath)

	sealInput1 := SealInput{outputblobFile: &outFile1, secretSourceData: &secretData1}
	sealInput2 := SealInput{outputblobFile: &outFile2, secretSourceData: &secretData2}

	// No parent handle file exists yet
	if err := Seal(tpmDevice, sealInput1); err != nil {
		t.Fatalf("Encountered error for first TPM seal %v, with input: %v", err, sealInput1.String())
	}

	// Now parent handle exists, should still work
	if err := Seal(tpmDevice, sealInput2); err != nil {
		t.Fatalf("Encountered error for second TPM seal %v, with input: %v", err, sealInput2.String())
	}

	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err != nil {
		t.Fatalf("Encountered error during flush context %v", err)
	}

	deleteSealFiles(outFile1)
	deleteSealFiles(outFile2)
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

func TestFlushContextNoTPM(t *testing.T) {

	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	parentHandle := uint32(RetrieveParentHandle(parentHandleFileName))

	// Cleanup
	if err := FlushContext(tpmDevice, &parentHandle); err == nil {
		t.Fatal("Expected error for wrong TPM path")
	}
}

func TestSealBadPath(t *testing.T) {

	secretData := "SecretString"
	outFile := "outfile"
	tpmPath := "/dev/noTPM"
	tpmDevice := NewTPMDevice(&tpmPath)
	sealInput := SealInput{outputblobFile: &outFile, secretSourceData: &secretData}

	if err := Seal(tpmDevice, sealInput); err == nil {
		t.Fatalf("error expected: tpm device not found %v", err)
	}

	deleteSealFiles(outFile)
}

func TestSealNoOutputFile(t *testing.T) {

	secretData := "SecretString"
	outFile := ""
	tpmPath := "/dev/noTPM"
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
