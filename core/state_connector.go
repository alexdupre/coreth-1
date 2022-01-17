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
	return &stateConnector{caller: caller, msg: msg}
}

type attestationVotes struct {
	reachedMajority    bool
	majorityDecision   string
	majorityAttestors  []common.Address
	divergentAttestors []common.Address
	abstainedAttestors []common.Address
}

func (c *stateConnector) finalisePreviousRound(chainID, timestamp *big.Int, currentRoundNumber []byte) error {
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
			// Make a back-up of the current state database, because this node is about to branch from the default set
		}
	} else if defaultAttestationVotes.reachedMajority {
		finalityReached = true
	}
	if !finalityReached {
		return nil
	}

	// Finalise defaultAttestationVotes.majorityDecision
	finalisedData := append(finaliseRoundSelector(chainID, timestamp), currentRoundNumber[:]...)
	merkleRootHashBytes, err := hex.DecodeString(defaultAttestationVotes.majorityDecision)
	if err != nil {
		return err
	}
	finalisedData = append(finalisedData[:], merkleRootHashBytes[:]...)
	coinbaseSignal := stateConnectorCoinbaseSignalAddr(chainID, timestamp)

	bc := c.caller.BlockContext()
	originalBC := bc
	defer func() {
		c.caller.WithBlockContext(originalBC)
	}()
	bc.Coinbase = coinbaseSignal
	c.caller.WithBlockContext(bc)

	_, _, err = c.caller.Call(vm.AccountRef(coinbaseSignal), c.to(), finalisedData, bc.GasLimit, new(big.Int).SetUint64(0))
	if err != nil {
		return err
	}

	// Issue rewards to defaultAttestationVotes.majorityAttestors here:

	return nil
}

func (c *stateConnector) countAttestations(attestors []common.Address, instructions []byte) attestationVotes {
	var av attestationVotes
	hashFrequencies := make(map[string][]common.Address)
	for i := range attestors {
		h, err := c.attestationResult(attestors[i], instructions)
		if err != nil {
			av.abstainedAttestors = append(av.abstainedAttestors, attestors[i])
		}
		hashFrequencies[h] = append(hashFrequencies[h], attestors[i])
	}
	// Find the plurality
	var pluralityNum int
	var pluralityKey string
	for key, val := range hashFrequencies {
		if len(val) > pluralityNum {
			pluralityNum = len(val)
			pluralityKey = key
		}
	}
	if pluralityNum > len(attestors)/2 {
		av.reachedMajority = true
		av.majorityDecision = pluralityKey
		av.majorityAttestors = hashFrequencies[pluralityKey]
	}
	for key, val := range hashFrequencies {
		if key != pluralityKey {
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
		attestors = append(attestors, common.BytesToAddress(priceProvidersBytes[i*common.HashLength:(i+1)*common.HashLength]))
	}
	return attestors, nil
}

func (c *stateConnector) attestationResult(attestor common.Address, instructions []byte) (string, error) {
	merkleRootHash, _, err := c.caller.Call(vm.AccountRef(attestor), c.to(), instructions, 20000, big.NewInt(0))
	return hex.EncodeToString(merkleRootHash), err
}

// to returns the recipient of the message.
func (c *stateConnector) to() common.Address {
	// empty message or receiver means contract creation
	if c.msg == nil || c.msg.To() == nil {
		return common.Address{}
	}
	return *c.msg.To()
}

func stateConnectorCoinbaseSignalAddr(chainID *big.Int, blockTime *big.Int) common.Address {
	switch {
	default:
		return common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	}
}

func attestationSelector(chainID *big.Int, blockTime *big.Int) []byte {
	switch {
	default:
		return []byte{0x29, 0xbe, 0x4d, 0xb2}
	}
}

func finaliseRoundSelector(chainID *big.Int, blockTime *big.Int) []byte {
	switch {
	default:
		return []byte{0xea, 0xeb, 0xf6, 0xd3}
	}
}

func voterWhitelisterSelector(chainID *big.Int, blockTime *big.Int) []byte {
	switch {
	default:
		return []byte{0x71, 0xe1, 0xfa, 0xd9}
	}
}

func ftsoWhitelistedPriceProvidersSelector(chainID *big.Int, blockTime *big.Int) []byte {
	switch {
	default:
		return []byte{0x09, 0xfc, 0xb4, 0x00}
	}
}

func localAttestors() []common.Address {
	envAttestationProvidersString := os.Getenv("LOCAL_ATTESTATION_PROVIDERS")
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
