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
// limitations under the License.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	//	"github.com/coinbase/rosetta-sdk-go/asserter"

	"github.com/coinbase/rosetta-sdk-go/client"
	"github.com/coinbase/rosetta-sdk-go/types"
	"golang.org/x/crypto/ed25519"
)

const (
	// serverURL is the URL of a Rosetta Server.
	//serverURL = "https://explorer.cardano-testnet.iohkdev.io/rosetta"
	serverURL = "Put your URL_server"
	// agent is the user-agent on requests to the
	// Rosetta Server.
	agent = "rosetta-sdk-go"

	// defaultTimeout is the default timeout for
	// HTTP requests.
	defaultTimeout      = 10 * time.Second
	receiverAdress      = "addr_test1vr0trgujtppfzu9cycsg55zyfr250qwnyzs8fxg7ahlmdrcuew8d2"
	receiverVerifiedKey = "5E47B3F3A8D4495BBE5A8CA5881D5E0BDDC935150072957002F387E8412457E6"
	receiverSecretKey   = "Put your Private Key"
	senderAdress        = "addr_test1vqgjd0t02q9yglcjwdc8dht9tz6gkfpqqm7evs5csrklakcqmwv40"
	userVerifiedKey     = "A23B39BDE998DEDE72791C0C8D02545F57B881C4A347F7A5856A4204324E9223"
	userSecretKey       = "Put your Private Key"
)

func main() {
	ctx := context.Background()

	// Step 1: Create a client
	clientCfg := client.NewConfiguration(
		serverURL,
		agent,
		&http.Client{
			Timeout: defaultTimeout,
		},
	)

	client := client.NewAPIClient(clientCfg)

	// Step 2: Get all available networks
	networkList, rosettaErr, err := client.NetworkAPI.NetworkList(
		ctx,
		&types.MetadataRequest{},
	)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}

	if len(networkList.NetworkIdentifiers) == 0 {
		log.Fatal("no available networks")
	}

	primaryNetwork := networkList.NetworkIdentifiers[0]

	// Step 3: Print the primary network
	log.Printf("Primary Network: %s\n", types.PrettyPrintStruct(primaryNetwork))
	// Step 4: Fetch the network status
	networkStatus, rosettaErr, err := client.NetworkAPI.NetworkStatus(
		ctx,
		&types.NetworkRequest{
			NetworkIdentifier: primaryNetwork,
		},
	)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	// Step 5: Print the response
	log.Printf("Network Status: %s\n", types.PrettyPrintStruct(networkStatus))

	//  Step 6: get the balance of our user
	accountBalanceRequest := types.AccountBalanceRequest{
		NetworkIdentifier: primaryNetwork,
		AccountIdentifier: &types.AccountIdentifier{Address: senderAdress, SubAccount: &types.SubAccountIdentifier{}, Metadata: map[string]interface{}{}},
		BlockIdentifier: &types.PartialBlockIdentifier{
			Index: &networkStatus.CurrentBlockIdentifier.Index,
			Hash:  &networkStatus.CurrentBlockIdentifier.Hash,
		},
	}

	accountBalance, rosettaErr, err := client.AccountAPI.AccountBalance(
		ctx, &accountBalanceRequest,
	)

	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}

	var counter int = 0
	for accountBalance.Balances[counter].Currency.Symbol != "ADA" && counter < len(accountBalance.Balances) {
		counter++

	}

	if accountBalance.Balances[counter].Currency.Symbol != "ADA" {
		log.Printf("Unable to get ADA balance")
	}

	fmt.Println(accountBalance.Balances[counter].Value)

	// Step 7: Get CoinIdentifier
	accountCoinsRequest := types.AccountCoinsRequest{
		NetworkIdentifier: primaryNetwork,
		AccountIdentifier: &types.AccountIdentifier{Address: senderAdress, SubAccount: &types.SubAccountIdentifier{}, Metadata: map[string]interface{}{}},
		IncludeMempool:    false, ////I have to chech this parameter
	}
	accountCoins, rosettaErr, err := client.AccountAPI.AccountCoins(
		ctx,
		&accountCoinsRequest,
	)

	var x []*types.Operation

	for i := 0; i < len(accountCoins.Coins); i++ {

		if accountCoins.Coins[i].Amount.Currency.Symbol == "ADA" {

			x = append(x, &types.Operation{
				OperationIdentifier: &types.OperationIdentifier{
					Index:        0,
					NetworkIndex: new(int64)},
				RelatedOperations: []*types.OperationIdentifier{},
				Type:              "input",
				Status:            new(string),
				Account: &types.AccountIdentifier{
					Address:    senderAdress,
					SubAccount: &types.SubAccountIdentifier{},
					Metadata:   map[string]interface{}{},
				},
				Amount: &types.Amount{
					Value: "-" + accountCoins.Coins[i].Amount.Value,
					Currency: &types.Currency{
						Symbol:   "ADA",
						Decimals: 6,
						Metadata: map[string]interface{}{},
					},
					Metadata: map[string]interface{}{},
				},
				CoinChange: &types.CoinChange{
					CoinIdentifier: &types.CoinIdentifier{
						Identifier: accountCoins.Coins[i].CoinIdentifier.Identifier,
					},
					CoinAction: "coin_spent",
				},
				Metadata: map[string]interface{}{},
			})
		}
	}

	log.Printf("request construction")

	operation_output := types.Operation{
		OperationIdentifier: &types.OperationIdentifier{
			Index:        1,
			NetworkIndex: new(int64)},
		RelatedOperations: []*types.OperationIdentifier{},
		Type:              "output",
		Status:            new(string),
		Account: &types.AccountIdentifier{
			Address:    receiverAdress,
			SubAccount: &types.SubAccountIdentifier{},
			Metadata:   map[string]interface{}{},
		},
		Amount: &types.Amount{
			Value: accountBalance.Balances[counter].Value,
			Currency: &types.Currency{
				Symbol:   "ADA",
				Decimals: 6,
				Metadata: map[string]interface{}{},
			},
			Metadata: map[string]interface{}{},
		},
		Metadata: map[string]interface{}{},
	}

	//fmt.Println(operation_input.Type)
	fmt.Println(operation_output.Type)

	x = append(x, &operation_output)

	transferRequest := types.ConstructionPreprocessRequest{
		NetworkIdentifier:      &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		Operations:             x,
		Metadata:               map[string]interface{}{},
		MaxFee:                 []*types.Amount{},
		SuggestedFeeMultiplier: new(float64),
	}
	fmt.Println(transferRequest.NetworkIdentifier.Blockchain)
	constructionPreprocessResponse, rosettaErr, err := client.ConstructionAPI.ConstructionPreprocess(ctx, &transferRequest)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}

	// Step: construct metadata
	decodedKeyArray, err := hex.DecodeString(userVerifiedKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyJson := types.PublicKey{
		Bytes:     decodedKeyArray,
		CurveType: "edwards25519",
	}

	constructionMetadataRequest := types.ConstructionMetadataRequest{
		NetworkIdentifier: &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		Options:           constructionPreprocessResponse.Options,
		PublicKeys:        []*types.PublicKey{&publicKeyJson},
	}
	constructionMetadataResponse, rosettaErr, err := client.ConstructionAPI.ConstructionMetadata(ctx, &constructionMetadataRequest)

	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	constructionMetadataResponse.SuggestedFee[0].Value = "164005"
	fmt.Println(constructionMetadataResponse.SuggestedFee[0].Value) // To check: Is it possible to have several suggested fee for one transactions???

	// Step: construct payload

	maxAmount, err := strconv.Atoi(operation_output.Amount.Value)

	if err != nil {
		log.Fatal(err)
	}
	suggestedFee, err := strconv.Atoi(constructionMetadataResponse.SuggestedFee[0].Value)

	if err != nil {
		log.Fatal(err)
	}
	//	fmt.Println(x[1].Amount.Value)
	//fmt.Println(x[2].Amount.Value)

	operation_output.Amount.Value = strconv.Itoa(maxAmount - suggestedFee)

	constructionPayloadRequest := types.ConstructionPayloadsRequest{
		NetworkIdentifier: &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		Operations:        x,
		Metadata:          constructionMetadataResponse.Metadata,
	}

	//	fmt.Println("amount  is " + x[1].Amount.Value)
	//fmt.Println(x[2].Amount.Value)
	fmt.Println("Payload construction")
	constructionPayloadResponse, rosettaErr, err := client.ConstructionAPI.ConstructionPayloads(ctx, &constructionPayloadRequest)

	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(constructionPayloadResponse.UnsignedTransaction)

	// Parse the unsigned transaction
	fmt.Println("request parsing")

	constructionParseRequest := types.ConstructionParseRequest{
		NetworkIdentifier: &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		Signed:            false,
		Transaction:       constructionPayloadResponse.UnsignedTransaction,
	}

	constructionParseResponse, rosettaErr, err := client.ConstructionAPI.ConstructionParse(ctx, &constructionParseRequest)
	fmt.Println("request parsing check")
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("trying to parse the transaction")
	log.Printf(constructionParseResponse.Operations[0].Type) // May be parse is not needed, only if you have to check that the transaction is well created.

	// step: sign the transaction

	fmt.Println("trying to sign the transaction 111")
	privb, _ := hex.DecodeString(userSecretKey)
	pubb, _ := hex.DecodeString(userVerifiedKey)
	pvk := ed25519.PrivateKey(privb)
	buffer := constructionPayloadResponse.Payloads[0].Bytes // to check why payloads [0] !!!!
	sigb := ed25519.Sign(pvk, buffer)
	signature := types.Signature{
		SigningPayload: &types.SigningPayload{
			AccountIdentifier: &types.AccountIdentifier{
				Address: senderAdress,
			},
			Bytes:         buffer,
			SignatureType: "ed25519",
		},
		PublicKey: &types.PublicKey{
			Bytes:     pubb,
			CurveType: "edwards25519",
		},
		SignatureType: "ed25519",
		Bytes:         sigb,
	}

	if !ed25519.Verify(pubb, buffer, sigb) {
		log.Printf("Error to sign the transaction: \n")
	}

	log.Printf("trying to sign the transaction")

	constructionCombineRequest := types.ConstructionCombineRequest{
		NetworkIdentifier:   &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		UnsignedTransaction: constructionPayloadResponse.UnsignedTransaction,
		Signatures:          []*types.Signature{&signature},
	}

	constructionCombineResponse, rosettaErr, err := client.ConstructionAPI.ConstructionCombine(ctx, &constructionCombineRequest)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(constructionCombineResponse.SignedTransaction)

	constructionSubmitRequest := types.ConstructionSubmitRequest{
		NetworkIdentifier: &types.NetworkIdentifier{Blockchain: "cardano", Network: "testnet", SubNetworkIdentifier: &types.SubNetworkIdentifier{}},
		SignedTransaction: constructionCombineResponse.SignedTransaction,
	}

	constructionSubmitResponse, rosettaErr, err := client.ConstructionAPI.ConstructionSubmit(ctx, &constructionSubmitRequest)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(constructionSubmitResponse.TransactionIdentifier.Hash)

	/*// Step 7: Fetch the network options
	networkOptions, rosettaErr, err := client.NetworkAPI.NetworkOptions(
		ctx,
		&types.NetworkRequest{
			NetworkIdentifier: primaryNetwork,
		},
	)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}

	// Step 8: Print the response
	//log.Printf("Network Options: %s\n", types.PrettyPrintStruct(networkOptions))
	// Step 9: Assert the response is valid
	err = asserter.NetworkOptionsResponse(networkOptions)
	if err != nil {
		log.Fatalf("Assertion Error: %s\n", err.Error())
	}
	// Step 10: Create an asserter using the retrieved NetworkStatus and
	// NetworkOptions.
	//
	// This will be used later to assert that a fetched block is
	// valid.
	_, err = asserter.NewClientWithResponses(
		primaryNetwork,
		networkStatus,
		networkOptions,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	// Step 11: Fetch the current block
	_, rosettaErr, err = client.BlockAPI.Block(
		ctx,
		&types.BlockRequest{
			NetworkIdentifier: primaryNetwork,
			BlockIdentifier: types.ConstructPartialBlockIdentifier(
				networkStatus.CurrentBlockIdentifier,
			),
		},
	)
	if rosettaErr != nil {
		log.Printf("Rosetta Error: %+v\n", rosettaErr)
	}
	if err != nil {
		log.Fatal(err)
	}

	// Step 12: Print the block
	/*	log.Printf("Current Block: %s\n", types.PrettyPrintStruct(block.Block))
		err = asserter.Block(block.Block)
		if err != nil {
			log.Fatalf("Assertion Error: %s\n", err.Error())
		}

		// Step 14: Print remaining transactions to fetch
		//
		// If you want the client to automatically fetch these, consider
		// using the fetcher package.
		for _, txn := range block.OtherTransactions {
			log.Printf("Other Transaction: %+v\n", txn)

		}*/
	// step 15: transfer ada

}
