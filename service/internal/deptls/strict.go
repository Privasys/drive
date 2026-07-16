package deptls

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// unmarshalStrict decodes JSON rejecting unknown fields, so a typo in a
// pasted dependency-set object fails loudly at configure time instead
// of silently weakening the pin.
func unmarshalStrict(raw string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(raw))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing content after the JSON object")
	}
	return nil
}
