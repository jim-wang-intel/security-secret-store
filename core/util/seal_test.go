package util

import (
	"testing"
)

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
