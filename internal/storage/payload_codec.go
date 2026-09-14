package storage

import (
	"encoding/json"
	"fmt"

	"github.com/GagarinRu/gophkeeper/internal/crypto"
)

func encodePayload(plain json.RawMessage, key []byte) (json.RawMessage, error) {
	if len(key) == 0 {
		return plain, nil
	}
	enc, err := crypto.EncryptAES(plain, key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(enc)
}

func decodePayload(stored json.RawMessage, key []byte) (json.RawMessage, error) {
	if len(key) == 0 {
		return stored, nil
	}
	var enc string
	if err := json.Unmarshal(stored, &enc); err != nil {
		return nil, fmt.Errorf("decode payload envelope: %w", err)
	}
	plain, err := crypto.DecryptAES(enc, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return json.RawMessage(plain), nil
}
