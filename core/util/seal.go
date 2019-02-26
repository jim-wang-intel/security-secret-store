/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package util

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm/tpm2"
)

const (
	emptyPassword         = ""
	parentHandleFileName  = "parentHndl"
	parentHandleSeparator = ","
	defaultTemplateType   = "RSA"
	defaultTemplate       = RSATemplate
)

// TemplateType is the type of template for EK Public Area
type TemplateType uint

const (
	// RSATemplate is the default EK public area template for creating primary key pairs
	// using RSA algorithm
	RSATemplate TemplateType = iota // the default template type if not explicitly specified
	// ECCTemplate is the EK public area template using Elliptic Curve Cryptographic algorithm
	ECCTemplate
)

func (template TemplateType) String() string {
	return [...]string{"RSA Template", "ECC Template"}[template]
}

// SealInput data passed into seal operation
type SealInput struct {
	SecretSourceData      *string
	OutputblobFile        *string
	PublicKeyTemplateType *string
}

// String toString method for SealInput
func (seal *SealInput) String() string {
	var outFileName, templateType string
	if seal.OutputblobFile != nil {
		outFileName = *seal.OutputblobFile
	}
	if seal.PublicKeyTemplateType != nil {
		templateType = *seal.PublicKeyTemplateType
	}
	return fmt.Sprintf("Output file name: %s, key template type: %s", outFileName, templateType)
}

// GetSRKTemplate is to create an instance of SRK template to be used in creating primary key
// from TPM device: the template type can be either RSA or ECC
func GetSRKTemplate(tempType TemplateType) (srkTemplate *tpm2.Public) {
	switch tempType {
	default:
		fallthrough
	case RSATemplate:
		srkTemplate = &tpm2.Public{
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
	case ECCTemplate:
		srkTemplate = &tpm2.Public{
			Type:       tpm2.AlgECC,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
			AuthPolicy: nil,
			ECCParameters: &tpm2.ECCParams{
				Symmetric: &tpm2.SymScheme{
					Alg:     tpm2.AlgAES,
					KeyBits: 128,
					Mode:    tpm2.AlgCFB,
				},
				CurveID: tpm2.CurveNISTP256,
				KDF:     &tpm2.KDFScheme{},
			},
		}
	}
	return srkTemplate
}

// Seal executes the Seal subcommands
func Seal(tpmDev *TPMDevice, sealInput SealInput) error {
	// nil pointer check:
	if sealInput.SecretSourceData == nil {
		return errors.New("empty secret not allow")
	}
	if sealInput.OutputblobFile == nil {
		return errors.New("output file path cannot be empty")
	}

	// default to RSA if nil or empty
	var templateTypeStr string
	if sealInput.PublicKeyTemplateType == nil {
		templateTypeStr = defaultTemplateType
	} else {
		templateTypeStr = strings.TrimSpace(*sealInput.PublicKeyTemplateType)
		if len(templateTypeStr) == 0 {
			// default to RSA
			templateTypeStr = defaultTemplateType
		}
	}

	secretInputBytes := []byte(*sealInput.SecretSourceData)
	outputblobFilePath := strings.TrimSpace(*sealInput.OutputblobFile)

	if len(secretInputBytes) == 0 {
		return errors.New("empty secret not allow")
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

	ownerPwd := emptyPassword
	srkPwd := emptyPassword

	var parentHandle tpmutil.Handle
	if _, err := os.Stat(parentHandleFileName); err == nil {
		// parent handle already exists, retrieve and reuse it
		parentHandle = RetrieveParentHandle(parentHandleFileName)
	} else if os.IsNotExist(err) {
		// maybe in the default location:

		var templateType TemplateType
		switch typeUpper := strings.ToUpper(templateTypeStr); typeUpper {
		case "RSA":
			templateType = RSATemplate
		case "ECC":
			templateType = ECCTemplate
		default:
			// unknown but assuming to be the default one
			log.Printf("Unknown template type sepcified %s and default to the %s template", templateTypeStr, defaultTemplateType)
			templateType = defaultTemplate
		}
		log.Printf("template type input: %s", templateType.String())
		srkTemplatePtr := GetSRKTemplate(templateType)
		srkHandle, _, primaryKeyErr := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{},
			ownerPwd, srkPwd, *srkTemplatePtr)
		if primaryKeyErr != nil {
			log.Printf("can't create primary key based on srkTemplate %v: %s", srkTemplatePtr, primaryKeyErr.Error())
			return primaryKeyErr
		}

		if writeHndlErr := writeParentHandleWithTemplateType(parentHandleFileName, srkHandle, &templateType); writeHndlErr != nil {
			log.Printf("error: %v\n", writeHndlErr)
		} else {
			log.Println("parent handle file successfully saved")
		}

		parentHandle = srkHandle
	} else {
		log.Printf("error on os stat parent handle: %v\n", err)
	}

	sessionHandle, policy, sessionPolicyGetErr := GetSimpleSessionPolicyWithPCR(rw)
	if policy == nil || sessionPolicyGetErr != nil {
		return sessionPolicyGetErr
	}

	defer func() {
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		log.Printf("sessionHandle 0x%x has been flushed\n", sessionHandle)
	}()

	// no password required
	objectPwd := emptyPassword
	sealPrivate, sealPublic, sealErr := tpm2.Seal(rw, parentHandle, srkPwd, objectPwd, policy, secretInputBytes)
	if sealErr != nil {
		return sealErr
	}

	log.Printf("secret is sealed with TPM: sealPrivate %v, sealPublic %v\n", sealPrivate, sealPublic)

	if writeErr := writeSealedData(outputblobFilePath, sealPrivate, sealPublic); writeErr != nil {
		return writeErr
	}
	log.Println("Seal screte with TPM device successfully done.")

	return nil
}

// GetSimpleSessionPolicyWithPCR returns simple authentication session with session policy
// the first return is sessionHandle,
// the second return is policy digest associated with it from TPM
// the third return is error if any
func GetSimpleSessionPolicyWithPCR(rw io.ReadWriter) (tpmutil.Handle, []byte, error) {
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
		log.Printf("unable to start session: %v\n", sessionErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		return tpm2.HandleNull, nil, sessionErr
	}

	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		// nil PCRs for now
		PCRs: nil,
	}
	if policyPCRErr := tpm2.PolicyPCR(rw, sessionHandle, nil /*expectedGigest*/, pcrSelection); policyPCRErr != nil {
		log.Printf("unable to bind PCRs to auth policy: %v\n", policyPCRErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		return tpm2.HandleNull, nil, policyPCRErr
	}
	if policyPwdErr := tpm2.PolicyPassword(rw, sessionHandle); policyPwdErr != nil {
		log.Printf("unable to require password for auth policy: %v\n", policyPwdErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		return tpm2.HandleNull, nil, policyPwdErr
	}
	policy, digestErr := tpm2.PolicyGetDigest(rw, sessionHandle)
	if digestErr != nil {
		log.Printf("unable to get policy digest: %v\n", digestErr)
		if flushErr := FlushSessionHandle(rw, sessionHandle); flushErr != nil {
			log.Printf("%v\n", flushErr)
		}
		return tpm2.HandleNull, nil, digestErr
	}
	return sessionHandle, policy, nil
}

// FlushSessionHandle removes the session context from TPM device with a given session handle
func FlushSessionHandle(rw io.ReadWriter, sessionHandle tpmutil.Handle) error {
	if sessionHandle != tpm2.HandleNull {
		log.Printf("flushing sessionHandle: 0x%x\n", sessionHandle)
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
		log.Printf("unable to read parent handle file [%s]: %v\n", handleFile, readErr)
		return tpm2.HandleNull
	}
	// the handleStr contains both parentHandle value and template type separated by comma (,)
	// i.e.: <parentHandleValue>,<templateType>
	handleStr := string(handleBytes)
	// so we just need the first element, the parent handle value
	handleStr = strings.Split(handleStr, parentHandleSeparator)[0]
	// base 0 means infer the base from the string
	if handleVal, convertErr := strconv.ParseUint(handleStr, 0, 32); convertErr != nil {
		log.Printf("unable to convert handle string %s, file [%s] may be corrupted: %v\n", handleStr, handleFile, convertErr)
		parentHandle = tpm2.HandleNull
	} else {
		parentHandle = tpmutil.Handle(uint32(handleVal))
	}

	return parentHandle
}

// GetTPMParentHandleFileName returns the file name path for parent handle
func GetTPMParentHandleFileName(outputblobFilePath string) string {
	baseFolder := filepath.Dir(outputblobFilePath)
	log.Printf("baseFolder %s\n", baseFolder)

	return filepath.Join(baseFolder, parentHandleFileName)
}

func writeParentHandleWithTemplateType(parentHandleFileName string, parentHandle tpmutil.Handle, templateType *TemplateType) error {
	templateTypeStr := templateType.String()
	contentToWrite := fmt.Sprintf("0x%x%s%s", parentHandle, parentHandleSeparator, templateTypeStr)
	log.Printf("contentToWrite: %s", contentToWrite)
	if writeErr := ioutil.WriteFile(parentHandleFileName, []byte(contentToWrite), 0644); writeErr != nil {
		return fmt.Errorf("cannot write the parent handle value to %s: %v", parentHandleFileName, contentToWrite)
	}
	return nil
}

func writeSealedData(outputblobFilePath string, sealPrivate, sealPublic []byte) error {
	privateFile := outputblobFilePath + ".prv"
	publicFile := outputblobFilePath + ".pub"

	if privateWriteErr := ioutil.WriteFile(privateFile, sealPrivate, 0644); privateWriteErr != nil {
		return fmt.Errorf("cannot write the private blob to %s: %v", privateFile, privateWriteErr)
	}

	log.Println("Successfully wrote the private blob file")

	if publicWriteErr := ioutil.WriteFile(publicFile, sealPublic, 0644); publicWriteErr != nil {
		return fmt.Errorf("cannot write the public blob to %s: %v", publicFile, publicWriteErr)
	}

	log.Println("Successfully wrote the public blob file")

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
