package hidproxy

import (
	"encoding/binary"
	"io"

	"github.com/fxamacker/cbor/v2"
)

var encMode, _ = cbor.CTAP2EncOptions().EncMode()

const NamedPipePath = "\\\\.\\pipe\\ctaphid"

type Command byte

const (
	CommandEnumerate Command = iota + 1
	CommandStart
)

type Message struct {
	Command Command
	length  uint16
	Data    []byte
}

func ParseMessage(reader io.Reader) (Message, error) {
	cmd := make([]byte, 1)
	if _, err := io.ReadFull(reader, cmd); err != nil {
		return Message{}, err
	}

	bLen := make([]byte, 2)
	if _, err := io.ReadFull(reader, bLen); err != nil {
		return Message{}, err
	}
	length := binary.BigEndian.Uint16(bLen)

	bData := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(reader, bData); err != nil {
			return Message{}, err
		}
	}

	return Message{
		Command: Command(cmd[0]),
		length:  length,
		Data:    bData,
	}, nil
}

func NewMessage(cmd Command, data any) (Message, error) {
	msg := Message{
		Command: cmd,
	}

	b := make([]byte, 0)
	var err error
	if data != nil {
		b, err = encMode.Marshal(data)
		if err != nil {
			return Message{}, err
		}
	}

	msg.length = uint16(len(b))
	msg.Data = b

	return msg, nil
}

func (m *Message) WriteTo(w io.Writer) (n int64, err error) {
	totalLen := 0

	cmdLen, err := w.Write([]byte{byte(m.Command)})
	if err != nil {
		return 0, err
	}
	totalLen += cmdLen

	bLen := make([]byte, 2)
	binary.BigEndian.PutUint16(bLen, m.length)
	lengthLen, err := w.Write(bLen)
	if err != nil {
		return 0, err
	}
	totalLen += lengthLen

	dataLen, err := w.Write(m.Data)
	if err != nil {
		return 0, err
	}
	totalLen += dataLen

	return int64(totalLen), nil
}
