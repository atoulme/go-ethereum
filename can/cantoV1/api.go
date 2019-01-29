// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package canto

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/node"
	// types "github.com/ethereum/go-ethereum/core/types"
)

// List of errors
var (
	ErrNoStakeToAccessSubnet    = errors.New("no stake to join subnet")
	ErrNoStakeToBecomeValidator = errors.New("no stake to become a validator")
	ErrInsufficientStake        = errors.New("not enough funds to stake the minimum amount")

	Nodes []NodeInfo
)

// Using a file for canto contract. Will need to figure out how to contact a smart contract
// and query the address of the caller in order to verify if they have staked or not.
// lazy implementation. will need to parse the object that is given from the smart contract
// then we can properly asses if they are subnet allowed.
// output of subnet contract will be something like this:
// struct subnetUser {
// 	address userAddress;
// 	bool allowed;
// 	uint256 stakedAmount;
// 	uint256 subnetBalance;
// }
func checkContract(addrs common.Address) bool {
	cont, err := ioutil.ReadFile("/Users/daniel/Documents/daniel/Code/Canto/go-ethereum/can/dummySmartContract.txt")
	if err != nil {
		fmt.Println(err)
	}
	contents := string(cont)
	contents = strings.ToLower(contents)
	address := addrs.String()
	address = strings.ToLower(address)

	if len(cont) > 0 {
		return strings.Contains(contents, address)
	}
	return false
}

// PublicCantoAPI provides the canto RPC service that can be
// use publicly without security implications.
type PublicCantoAPI struct {
	c        *Canto
	mu       sync.Mutex
	lastUsed map[string]time.Time // keeps track when a filter was polled for the last time.
}

// NewPublicCantoAPI create a new RPC canto service.
func NewPublicCantoAPI(c *Canto) *PublicCantoAPI {
	api := &PublicCantoAPI{
		c:        c,
		lastUsed: make(map[string]time.Time),
	}
	return api
}

// Version returns the Canto sub-protocol version.
func (api *PublicCantoAPI) Version(ctx context.Context) string {
	return ProtocolVersionStr
}

// Info contains diagnostic information.
type NodeInfo struct {
	Address         common.Address
	HasSubnetAccess bool
	IsValidator     bool
	SubnetAddress   common.Address
	Stake           Stake
}

// Account is a copy of the struct from account.go
// needed to override the type and expose the members to interact with
type Account struct {
	Address common.Address `json:"address"` // Ethereum account address derived from the key
	URL     accounts.URL   `json:"url"`     // Optional resource locator within a backend
}

// Stake is the struct that will hold the information of the wallet's stake
type Stake struct {
	Amount     float64 `json:"amount"`
	HaveStaked bool    `json:"haveStaked"`
}

func (n NodeInfo) GetStakedAmount() float64 {
	return n.Stake.Amount
}

// Init will initizalize all the nodes addresses as a struct array
// will need to figure out how we can query the status of these nodes
// currentlty overwriting the data that is inside the fields of these
// addresses everytime this function is called to initialize acc info
func (api *PublicCantoAPI) Init(ctx context.Context) {
	keydir := node.DefaultDataDir() + "/keystore"
	keyStore := keystore.NewKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
	accounts := keyStore.Accounts()
	accInfo := make([]NodeInfo, 0)
	for _, account := range accounts {
		accInfo = append(accInfo, NodeInfo{
			Address:         Account(account).Address,
			HasSubnetAccess: checkContract(Account(account).Address),
			IsValidator:     false,
			// Stake: Stake{
			// 	Amount:     0,
			// 	HaveStaked: checkContract(Account(account).Address),
			// },
		})
	}
	Nodes = accInfo
}

// Info returns diagnostic information about the canto node.
func (api *PublicCantoAPI) Info(ctx context.Context) []NodeInfo {
	if len(Nodes) != 0 {
		return Nodes
	}
	api.Init(ctx)
	return Nodes
}

// Stake will get the values from NodeInfo and it will evalutate if the account needs
// to stake to be allowed access to the subnets
func (api *PublicCantoAPI) Stake(ctx context.Context, addr int) float64 {
	if len(Nodes) == 0 {
		api.Init(ctx)
	}
	fmt.Println("I WANT TO STAKE")
	if Nodes[addr].Stake.Amount < minStakeValue {
		// eth.getBalance("0xdae4fd0483409538e0e9beecaf5f1c9096b2b9e3")
		// use this call to find the balance of the wallet address
		fmt.Println("Not enough staked, here is some eth for now you poor ass")
		Nodes[addr].Stake.Amount += 10
		return Nodes[addr].Stake.Amount
	}
	// need to implement the eth.sendTransaction function here so we can send a transaction
	// to the contract. impl is written below but still need to figure out how to properly get
	// the nonce of the account
	// also need to generate the key to sign the transaction
	// signer := types.HomesteadSigner{}
	// key := crypto.HexToECDSA(" < key > ")
	// tx, _ := types.SignTx(types.NewTransaction(0, Nodes[addr].Address, big.NewInt(minStakeValue), params.TxGas, nil, nil), signer, key)
	// gen.AddTx(tx)
	Nodes[addr].Stake.Amount -= minStakeValue
	Nodes[addr].Stake.HaveStaked = true
	return Nodes[addr].Stake.Amount
}

// func (api *PublicCantoAPI) CheckSubenetStatus() bool {

// }

// Help returns all the methods available for the canto subprotocol
// func (api *PublicCantoAPI) Help(ctx context.Context) []string {
// 	// just for convenience during development. Will be taken out or cleaned up later
// 	output := []string{"Version", "Info"}
// 	return output
// }

// MarkTrustedPeer marks a peer trusted, which will allow it to send historic (expired) messages.
// Note: This function is not adding new nodes, the node needs to exists as a peer.
// func (api *PublicCantoAPI) MarkTrustedPeer(ctx context.Context, url string) (bool, error) {
// 	n, err := enode.ParseV4(url)
// 	if err != nil {
// 		return false, err
// 	}
// 	return true, api.c.AllowP2PMessagesFromPeer(n.ID().Bytes())
// }
