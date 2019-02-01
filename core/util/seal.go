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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm/tpm2"
)

const (
	emptyPassword        = ""
	parentHandleFileName = "parentHndl"
)

// SealInput data passed into seal operation
type SealInput struct {
	secretSourceData *string
	outputblobFile   *string
}

// String toString method for SealInput
func (seal *SealInput) String() string {
	return fmt.Sprintf("Output file name: %s", *seal.outputblobFile)
}

// GetSRKTemplate is to create an instance of SRK template to be used in creating primary key
// from TPM device
func GetSRKTemplate() *tpm2.Public {
	return &tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256),
		},
	}
}

// Seal executes the Seal subcommands
func Seal(tpmDev *TPMDevice, sealInput SealInput) error {

	secretInputBytes := []byte(*sealInput.secretSourceData)
	outputblobFilePath := strings.TrimSpace(*sealInput.outputblobFile)

	if len(secretInputBytes) == 0 {
		return errors.New("empty secret")
	}

	if len(outputblobFilePath) == 0 {
		return errors.New("output file path cannot be empty")
	}

	rw, err := tpmDev.OpenTPMDevice()
	if err != nil {
		return err
	}
	defer rw.Close()

	// load the parent handle and object handle from the file
	parentHandleFileName := GetTPMParentHandleFileName(outputblobFilePath)
	//clearTpmHandles(rw, tpmHandleFiles)

	ownerPwd := emptyPassword
	srkPwd := emptyPassword

	var parentHandle tpmutil.Handle
	if _, err := os.Stat(parentHandleFileName); err == nil {
		// parent handle already exists, retrieve and reuse it
		parentHandle = RetrieveParentHandle(parentHandleFileName)
	} else if os.IsNotExist(err) {
		srkTemplatePtr := GetSRKTemplate()
		srkHandle, _, primaryKeyErr := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{},
			ownerPwd, srkPwd, *srkTemplatePtr)
		if primaryKeyErr != nil {
			// log.Fatalf("can't create primary key based on srkTemplate %v: %s", srkTemplatePtr, primaryKeyErr.Error())
			return primaryKeyErr
		}

		if writeHndlErr := writeParentHandle(parentHandleFileName, srkHandle); writeHndlErr != nil {
			fmt.Printf("error: %v\n", writeHndlErr)
		} else {
			fmt.Println("parent handle file successfully saved")
		}

		parentHandle = srkHandle
	} else {
		fmt.Printf("error on os stat parent handle: %v\n", err)
	}

	// read PCR for binding with policy in the session
	// here we just tempoararily use 0 value to start with
	// as we do not enforce the PCR binding for this time
	pcr := 0
	pcrVal, pcrErr := tpm2.ReadPCR(rw, pcr, tpm2.AlgSHA256)
	if pcrErr != nil {
		fmt.Printf("unable to read PCR: %v\n", pcrErr)
	}
	fmt.Printf("PCR %v value: 0x%x\n", pcr, pcrVal)

	sessionHandle, _, sessionErr := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)

	if sessionErr != nil {
		fmt.Printf("unable to start session: %v\n", sessionErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			fmt.Printf("%v\n", flushErr)
		}
		return sessionErr
	}
	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{pcr},
	}
	if policyPCRErr := tpm2.PolicyPCR(rw, sessionHandle, nil /*expectedGigest*/, pcrSelection); policyPCRErr != nil {
		fmt.Printf("unable to bind PCRs to auth policy: %v\n", policyPCRErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			fmt.Printf("%v\n", flushErr)
		}
		return policyPCRErr
	}
	if policyPwdErr := tpm2.PolicyPassword(rw, sessionHandle); policyPwdErr != nil {
		fmt.Printf("unable to require password for auth policy: %v\n", policyPwdErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			fmt.Printf("%v\n", flushErr)
		}
		return policyPwdErr
	}
	policy, digestErr := tpm2.PolicyGetDigest(rw, sessionHandle)
	if digestErr != nil {
		fmt.Printf("unable to get policy digest: %v\n", digestErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			fmt.Printf("%v\n", flushErr)
		}
		return digestErr
	}

	if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
		fmt.Printf("%v\n", flushErr)
		return flushErr
	}

	objectPwd := "test"
	sealPrivate, sealPublic, sealErr := tpm2.Seal(rw, parentHandle, srkPwd, objectPwd, policy, secretInputBytes)
	if sealErr != nil {
		return sealErr
	}

	fmt.Printf("secret is sealed with TPM: sealPrivate %v, sealPublic %v\n", sealPrivate, sealPublic)

	if writeErr := writeSealedData(outputblobFilePath, sealPrivate, sealPublic); writeErr != nil {
		return writeErr
	}
	fmt.Println("Seal screte with TPM device successfully done.")

	return nil
}

// FlushSessionHandle removes the session context from TPM device with a given session handle
func FlushSessionHandle(rw io.ReadWriter, sessionHandle tpmutil.Handle) error {
	if sessionHandle != tpm2.HandleNull {
		fmt.Printf("flushing sessionHandle: 0x%x\n", sessionHandle)
		if flushErr := tpm2.FlushContext(rw, sessionHandle); flushErr != nil {
			return fmt.Errorf("unable to flush session: %v", flushErr)
		}
	}
	return nil
}

// RetrieveParentHandle reads the parent handle value from handleFile
func RetrieveParentHandle(handleFile string) (parentHandle tpmutil.Handle) {
	handleBytes, readErr := ioutil.ReadFile(handleFile)
	if readErr != nil {
		// file reading error; skip
		fmt.Printf("unable to read parent handle file [%s]: %v\n", handleFile, readErr)
		return tpm2.HandleNull
	}

	handleStr := string(handleBytes)
	// base 0 means infer the base from the string
	if handleVal, convertErr := strconv.ParseUint(handleStr, 0, 32); convertErr != nil {
		fmt.Printf("unable to convert handle string %s, file [%s] may be corrupted: %v\n", handleStr, handleFile, convertErr)
		parentHandle = tpm2.HandleNull
	} else {
		parentHandle = tpmutil.Handle(uint32(handleVal))
	}

	return parentHandle
}

// GetTPMParentHandleFileName returns the file name path for parent handle
func GetTPMParentHandleFileName(outputblobFilePath string) string {
	baseFolder := filepath.Dir(outputblobFilePath)
	fmt.Printf("baseFolder %s\n", baseFolder)

	return filepath.Join(baseFolder, parentHandleFileName)
}

func writeParentHandle(parentHandleFileName string, parentHandle tpmutil.Handle) error {
	handleHexVal := fmt.Sprintf("0x%x", parentHandle)
	fmt.Printf("handleHexVal: %s\n", handleHexVal)
	if writeErr := ioutil.WriteFile(parentHandleFileName, []byte(handleHexVal), 0644); writeErr != nil {
		return fmt.Errorf("cannot write the parent handle value to %s: %v", parentHandleFileName, handleHexVal)
	}
	return nil
}

func writeSealedData(outputblobFilePath string, sealPrivate, sealPublic []byte) error {
	privateFile := outputblobFilePath + ".prv"
	publicFile := outputblobFilePath + ".pub"

	if privateWriteErr := ioutil.WriteFile(privateFile, sealPrivate, 0644); privateWriteErr != nil {
		return fmt.Errorf("cannot write the private blob to %s: %v", privateFile, privateWriteErr)
	}

	fmt.Println("Successfully wrote the private blob file")

	if publicWriteErr := ioutil.WriteFile(publicFile, sealPublic, 0644); publicWriteErr != nil {
		return fmt.Errorf("cannot write the public blob to %s: %v", publicFile, publicWriteErr)
	}

	fmt.Println("Successfully wrote the public blob file")

	return nil
}

func deleteSealFiles(file string) {

	dir, _ := os.Getwd()
	privateFile := file + ".prv"
	publicFile := file + ".pub"
	privateFilePath := path.Join(dir, privateFile)
	publicFilePath := path.Join(dir, publicFile)

	os.Remove(privateFilePath)
	os.Remove(publicFilePath)
}
