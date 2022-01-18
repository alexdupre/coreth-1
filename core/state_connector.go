// (c) 2021, Flare Networks Limited. All rights reserved.
// Please see the file LICENSE for licensing terms.

package core

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/flare-foundation/coreth/core/vm"
)

const envLocalAttestationProviders = "LOCAL_ATTESTATION_PROVIDERS"

var stateConnectorCoinbaseSignalAddr = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

type Caller interface {
	Call(caller vm.ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error)
	WithBlockContext(bc vm.BlockContext)
	BlockContext() vm.BlockContext
}

// stateConnector is responsible for calling state connector smart contract based on votes from attestors
type stateConnector struct {
	caller Caller
	msg    Message
}

func newConnector(caller Caller, msg Message) *stateConnector {
	s := &stateConnector{
		caller: caller,
		msg:    msg,
	}
	return s
}

type attestationVotes struct {
	reachedMajority    bool
	majorityDecision   string
	majorityAttestors  []common.Address
	divergentAttestors []common.Address
	abstainedAttestors []common.Address
}

func (c *stateConnector) finalizePreviousRound(chainID, timestamp *big.Int, currentRoundNumber []byte) error {
	instructions := append(attestationSelector(chainID, timestamp), currentRoundNumber[:]...)
	defaultAttestors, err := c.defaultAttestors(chainID, timestamp)
	if err != nil {
		return err
	}
	defaultAttestationVotes := c.countAttestations(defaultAttestors, instructions)
	localAttestors := localAttestors()
	var finalityReached bool
	if len(localAttestors) > 0 {
		localAttestationVotes := c.countAttestations(localAttestors, instructions)
		if defaultAttestationVotes.reachedMajority && localAttestationVotes.reachedMajority && defaultAttestationVotes.majorityDecision == localAttestationVotes.majorityDecision {
			finalityReached = true
		} else if defaultAttestationVotes.reachedMajority && defaultAttestationVotes.majorityDecision != localAttestationVotes.majorityDecision {
			// FIXME Make a back-up of the current state database, because this node is about to branch from the default set
		}
	} else if defaultAttestationVotes.reachedMajority {
		finalityReached = true
	}
	if !finalityReached {
		return nil
	}

	// Finalise defaultAttestationVotes.majorityDecision
	finalizedData := append(finalizeRoundSelector(chainID, timestamp), currentRoundNumber[:]...)
	merkleRootHashBytes, err := hex.DecodeString(defaultAttestationVotes.majorityDecision)
	if err != nil {
		return err
	}
	finalizedData = append(finalizedData[:], merkleRootHashBytes[:]...)
	bc := c.caller.BlockContext()

	// FIXME add a comment why are we swapping the coinbase address
	originalBC := bc
	defer func() {
		c.caller.WithBlockContext(originalBC)
	}()
	bc.Coinbase = stateConnectorCoinbaseSignalAddr
	c.caller.WithBlockContext(bc)

	_, _, err = c.caller.Call(vm.AccountRef(stateConnectorCoinbaseSignalAddr), c.to(), finalizedData, bc.GasLimit, new(big.Int).SetUint64(0))
	if err != nil {
		return err
	}

	// FIXME Issue rewards to defaultAttestationVotes.majorityAttestors here:

	return nil
}

// countAttestations counts the number of the votes and determines whether majority is reached
func (c *stateConnector) countAttestations(attestors []common.Address, instructions []byte) attestationVotes {
	var av attestationVotes
	hashFrequencies := make(map[string][]common.Address, len(attestors))
	for i := range attestors {
		h, err := c.attestationResult(attestors[i], instructions)
		if err != nil {
			av.abstainedAttestors = append(av.abstainedAttestors, attestors[i])
		}
		hashFrequencies[h] = append(hashFrequencies[h], attestors[i])
	}
	var majorityNum int
	var majorityKey string
	for key, val := range hashFrequencies {
		if len(val) > majorityNum {
			majorityNum = len(val)
			majorityKey = key
		}
	}
	if majorityNum > len(attestors)/2 {
		av.reachedMajority = true
		av.majorityDecision = majorityKey
		av.majorityAttestors = hashFrequencies[majorityKey]
	}
	for key, val := range hashFrequencies {
		if key != majorityKey {
			av.divergentAttestors = append(av.divergentAttestors, val...)
		}
	}
	return av
}

// defaultAttestors returns list of FTSO price providers which represents the default attestors.
func (c *stateConnector) defaultAttestors(chainID *big.Int, timestamp *big.Int) ([]common.Address, error) {
	bc := c.caller.BlockContext()

	// Get VoterWhitelister contract
	voterWhitelisterContractBytes, _, err := c.caller.Call(
		vm.AccountRef(c.msg.From()),
		common.HexToAddress(GetPrioritisedFTSOContract(timestamp)),
		voterWhitelisterSelector(chainID, timestamp),
		GetKeeperGasMultiplier(bc.BlockNumber)*bc.GasLimit,
		big.NewInt(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get VoterWhitelister contract: %w", err)
	}

	// Get FTSO price providers
	voterWhitelisterContract := common.BytesToAddress(voterWhitelisterContractBytes)
	priceProvidersBytes, _, err := c.caller.Call(
		vm.AccountRef(c.msg.From()),
		voterWhitelisterContract,
		ftsoWhitelistedPriceProvidersSelector(chainID, timestamp),
		GetKeeperGasMultiplier(bc.BlockNumber)*bc.GasLimit,
		big.NewInt(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get FTSO price providers: %w", err)
	}

	attestorsNum := len(priceProvidersBytes) / common.HashLength
	var attestors []common.Address
	for i := 0; i < attestorsNum; i++ {
		startIndex := i * common.HashLength
		endIndex := (i + 1) * common.HashLength
		attestors = append(attestors, common.BytesToAddress(priceProvidersBytes[startIndex:endIndex]))
	}
	return attestors, nil
}

func (c *stateConnector) attestationResult(attestor common.Address, instructions []byte) (string, error) {
	rootHash, _, err := c.caller.Call(vm.AccountRef(attestor), c.to(), instructions, 20000, big.NewInt(0))
	return hex.EncodeToString(rootHash), err
}

func localAttestors() []common.Address {
	envAttestationProvidersString := os.Getenv(envLocalAttestationProviders)
	if envAttestationProvidersString == "" {
		return nil
	}
	envAttestationProviders := strings.Split(envAttestationProvidersString, ",")
	attestors := make([]common.Address, len(envAttestationProviders))
	for i := range envAttestationProviders {
		attestors[i] = common.HexToAddress(envAttestationProviders[i])
	}
	return attestors
}

// to returns the recipient of the message.
func (c *stateConnector) to() common.Address {
	// empty message or receiver means contract creation
	if c.msg == nil || c.msg.To() == nil {
		return common.Address{}
	}
	return *c.msg.To()
}

func attestationSelector(chainID *big.Int, blockTime *big.Int) []byte {
	return []byte{0x29, 0xbe, 0x4d, 0xb2}
}

func finalizeRoundSelector(chainID *big.Int, blockTime *big.Int) []byte {
	return []byte{0xea, 0xeb, 0xf6, 0xd3}
}

func voterWhitelisterSelector(chainID *big.Int, blockTime *big.Int) []byte {
	return []byte{0x71, 0xe1, 0xfa, 0xd9}
}

func ftsoWhitelistedPriceProvidersSelector(chainID *big.Int, blockTime *big.Int) []byte {
	return []byte{0x09, 0xfc, 0xb4, 0x00}
}
