package session

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mailgun/lemma/random"
	"github.com/mailgun/lemma/secret"
)

// Secure encrypted session id
type SecureID string

// Plain text unique session id
type PlainID string

// IDPair is a pair of unique and encrypted session id
type IDPair struct {
	SID SecureID
	PID PlainID
}

func NewID(s secret.SecretService) (*IDPair, error) {
	p := &random.CSPRNG{}
	bytes, err := p.Bytes(32)
	if err != nil {
		return nil, err
	}
	pid := []byte(hex.EncodeToString(bytes))
	sealed, err := s.Seal(pid)
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%v.%v",
		sealed.CiphertextHex(),
		sealed.NonceHex())
	return &IDPair{SID: SecureID(id), PID: PlainID(pid)}, nil
}

func DecodeSID(sid SecureID, s secret.SecretService) (PlainID, error) {
	out := strings.Split(string(sid), ".")
	if len(out) != 2 {
		return "", &MalformedSessionError{S: sid, Msg: "invalid format, missing separator"}
	}
	ctext, err := base64.URLEncoding.DecodeString(out[0])
	if err != nil {
		return "", &MalformedSessionError{S: sid, Msg: err.Error()}
	}
	nonce, err := base64.URLEncoding.DecodeString(out[1])
	if err != nil {
		return "", &MalformedSessionError{S: sid, Msg: err.Error()}
	}
	id, err := s.Open(&secret.SealedBytes{Ciphertext: ctext, Nonce: nonce})
	if err != nil {
		return "", &MalformedSessionError{S: sid, Msg: err.Error()}
	}
	return PlainID(id), nil
}

type MalformedSessionError struct {
	S   SecureID
	Msg string
}

func (m *MalformedSessionError) Error() string {
	return fmt.Sprintf("malformed session: %v", m.Msg)
}
