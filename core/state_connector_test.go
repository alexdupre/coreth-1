package core

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/flare-foundation/coreth/core/types"
	"github.com/flare-foundation/coreth/core/vm"
)

type mockMessage struct {
	from       common.Address
	to         common.Address
	gas        uint64
	gasPrice   *big.Int
	gasFeeCap  *big.Int
	gasTipCap  *big.Int
	value      *big.Int
	data       []byte
	accessList types.AccessList
}

func (m *mockMessage) From() common.Address         { return m.from }
func (m *mockMessage) To() *common.Address          { return &m.to }
func (m *mockMessage) GasPrice() *big.Int           { return m.gasPrice }
func (m *mockMessage) GasFeeCap() *big.Int          { return m.gasFeeCap }
func (m *mockMessage) GasTipCap() *big.Int          { return m.gasTipCap }
func (m *mockMessage) Value() *big.Int              { return m.value }
func (m *mockMessage) Gas() uint64                  { return m.gas }
func (m *mockMessage) Nonce() uint64                { return 0 }
func (m *mockMessage) Data() []byte                 { return m.data }
func (m *mockMessage) AccessList() types.AccessList { return m.accessList }
func (m *mockMessage) IsFake() bool                 { return true }

type mockStateConnectorCaller struct {
	context  vm.BlockContext
	testCase string
	msg      *mockMessage
}

func (m *mockStateConnectorCaller) Call(caller vm.ContractRef, addr common.Address, input []byte, gas uint64,
	value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	switch {
	case m.testCase == "happy_path" || m.testCase == "finalized_data_error":
		voter1 := common.BytesToHash([]byte("voter1"))
		voter2 := common.BytesToHash([]byte("voter2"))
		merkleRootHash := []byte("some_hash")

		if caller == vm.AccountRef(m.msg.From()) {
			if addr == common.HexToAddress(GetPrioritisedFTSOContract(nil)) {
				return []byte("voter"), 0, nil
			}
			if addr == common.BytesToAddress([]byte("voter")) {
				return append([]byte{}, append(voter1.Bytes(), voter2.Bytes()...)...), 0, nil
			}
		}
		if caller == vm.AccountRef(common.BytesToAddress(voter1.Bytes())) ||
			caller == vm.AccountRef(common.BytesToAddress(voter2.Bytes())) {
			return merkleRootHash, 0, nil
		}
		if caller == vm.AccountRef(stateConnectorCoinbaseSignalAddr) {
			if m.context.Coinbase != stateConnectorCoinbaseSignalAddr {
				return nil, 0, fmt.Errorf("invalid coinbase address: expected %v, got %v", stateConnectorCoinbaseSignalAddr, m.context.Coinbase)
			}
			if m.testCase == "happy_path" {
				return nil, 0, nil
			}
			return nil, 0, errors.New("finalization error")
		}
	case m.testCase == "default_attestors_error_1":
		return nil, 0, errors.New("voter whitelister error")
	case m.testCase == "default_attestors_error_2":
		switch addr {
		case common.HexToAddress(GetPrioritisedFTSOContract(nil)):
			return []byte("voter"), 0, nil
		case common.BytesToAddress([]byte("voter")):
			return nil, 0, errors.New("list price provider error")
		}
	}
	return nil, 0, errors.New("undefined test case")
}

func (m *mockStateConnectorCaller) WithBlockContext(bc vm.BlockContext) { m.context = bc }

func (m *mockStateConnectorCaller) BlockContext() vm.BlockContext { return m.context }

func TestStateTransition_FinalisePreviousRound(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		mockMsg := &mockMessage{
			from: common.BytesToAddress([]byte("happy_path")),
		}
		mockSCC := &mockStateConnectorCaller{
			testCase: "happy_path",
			msg:      mockMsg,
			context: vm.BlockContext{
				Coinbase: common.BigToAddress(big.NewInt(1000)),
			},
		}
		c := newConnector(mockSCC, mockMsg)
		currentRoundNumber := []byte("222")
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.NoError(t, err)
		assert.Equal(t, common.BigToAddress(big.NewInt(1000)), mockSCC.context.Coinbase, "coinbase address should be changed to the original address")
	})
	t.Run("default_attestors_error_1", func(t *testing.T) {
		mockMsg := &mockMessage{
			from: common.BytesToAddress([]byte("default_attestors_error_1")),
		}
		mockSCC := &mockStateConnectorCaller{
			testCase: "default_attestors_error_1",
			msg:      mockMsg,
		}
		c := newConnector(mockSCC, mockMsg)
		currentRoundNumber := []byte("222")
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "failed to get VoterWhitelister contract: voter whitelister error")
	})
	t.Run("default_attestors_error_2", func(t *testing.T) {
		mockMsg := &mockMessage{
			from: common.BytesToAddress([]byte("default_attestors_error_2")),
		}
		mockSCC := &mockStateConnectorCaller{
			testCase: "default_attestors_error_2",
			msg:      mockMsg,
		}
		c := newConnector(mockSCC, mockMsg)
		currentRoundNumber := []byte("222")
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "failed to get FTSO price providers: list price provider error")
	})
	t.Run("finalized_data_error", func(t *testing.T) {
		mockMsg := &mockMessage{
			from: common.BytesToAddress([]byte("finalized_data_error")),
		}
		mockSCC := &mockStateConnectorCaller{
			testCase: "finalized_data_error",
			msg:      mockMsg,
			context: vm.BlockContext{
				Coinbase: common.BigToAddress(big.NewInt(1000)),
			},
		}
		c := newConnector(mockSCC, mockMsg)
		currentRoundNumber := []byte("222")
		err := c.finalizePreviousRound(big.NewInt(10), big.NewInt(10), currentRoundNumber)
		assert.EqualError(t, err, "finalization error")
		assert.Equal(t, common.BigToAddress(big.NewInt(1000)), mockSCC.context.Coinbase, "coinbase address should be changed to the original address")
	})
}
