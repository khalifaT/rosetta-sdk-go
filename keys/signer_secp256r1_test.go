// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coinbase/rosetta-sdk-go/types"
)

var signerSecp256r1 Signer

func init() {
	keypair, _ := GenerateKeypair(types.Secp256r1)
	signerSecp256r1, _ = keypair.Signer()
}

func TestSignSecp256r1(t *testing.T) {
	type payloadTest struct {
		payload *types.SigningPayload
		sigType types.SignatureType
		sigLen  int
		err     bool
		errMsg  error
	}

	var payloadTests = []payloadTest{
		{mockPayload(hash("hello1234"), types.Ecdsa), types.Ecdsa, 64, false, nil},
		{
			mockPayload(hash("hello1234"), types.EcdsaRecovery),
			types.EcdsaRecovery,
			65,
			true,
			ErrSignUnsupportedSignatureType,
		},
		{
			mockPayload(hash("hello1234"), types.Ed25519),
			types.Ed25519,
			64,
			true,
			ErrSignUnsupportedSignatureType,
		},
		{
			mockPayload(hash("hello1234"), types.Schnorr1),
			types.Schnorr1,
			64, true,
			ErrSignUnsupportedSignatureType,
		},
	}

	for _, test := range payloadTests {
		signature, err := signerSecp256r1.Sign(test.payload, test.sigType)

		if !test.err {
			assert.NoError(t, err)
			assert.Equal(t, len(signature.Bytes), test.sigLen)
			assert.Equal(t, signerSecp256r1.PublicKey(), signature.PublicKey)
		} else {
			assert.Contains(t, err.Error(), test.errMsg.Error())
		}
	}
}

func TestVerifySecp256r1(t *testing.T) {
	type signatureTest struct {
		signature *types.Signature
		errMsg    error
	}

	payloadEcdsa := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: "test"},
		Bytes:             hash("hello"),
		SignatureType:     types.Ecdsa,
	}
	testSignatureEcdsa, err := signerSecp256r1.Sign(payloadEcdsa, types.Ecdsa)
	assert.NoError(t, err)

	simpleBytes := make([]byte, 33)
	copy(simpleBytes, "hello")

	var signatureTests = []signatureTest{
		{mockSecpSignature(
			types.Ed25519,
			signerSecp256r1.PublicKey(),
			hash("hello"),
			simpleBytes), ErrVerifyUnsupportedSignatureType},
		{mockSecpSignature(
			types.Ecdsa,
			signerSecp256r1.PublicKey(),
			hash("hello"),
			simpleBytes), ErrVerifyFailed},
		{mockSecpSignature(
			types.EcdsaRecovery,
			signerSecp256r1.PublicKey(),
			hash("hello"),
			simpleBytes), ErrVerifyUnsupportedSignatureType},
		{mockSecpSignature(
			types.Schnorr1,
			signerSecp256r1.PublicKey(),
			hash("hello"),
			simpleBytes), ErrVerifyUnsupportedSignatureType},
	}

	for _, test := range signatureTests {
		err := signerSecp256r1.Verify(test.signature)
		assert.Contains(t, err.Error(), test.errMsg.Error())
	}

	goodEcdsaSignature := mockSecpSignature(
		types.Ecdsa,
		signerSecp256r1.PublicKey(),
		hash("hello"),
		testSignatureEcdsa.Bytes)
	assert.Equal(t, nil, signerSecp256r1.Verify(goodEcdsaSignature))
}
