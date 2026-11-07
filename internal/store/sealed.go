package store

import (
	"errors"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

var errNoSealer = errors.New("store: encryption keys are not configured (set DATA_KEY and DATA_PEPPER)")

// SetSealer turns on encryption at rest. It also installs the keyed hasher in
// package normalize, so lookup keys are HMACs and match what is stored.
// It must be called before Migrate and before any entry is read or written.
func (s *Store) SetSealer(sl *seal.Sealer) {
	s.sealer = sl
	normalize.SetHasher(sl.Hasher())
}

// sealNoteSource encrypts the two free-text columns of an entry.
func (s *Store) sealNoteSource(note, source string) (noteEnc, sourceEnc []byte, err error) {
	if s.sealer == nil {
		return nil, nil, errNoSealer
	}

	if noteEnc, err = s.sealer.Seal(note, seal.AADNote); err != nil {
		return nil, nil, err
	}

	if sourceEnc, err = s.sealer.Seal(source, seal.AADSource); err != nil {
		return nil, nil, err
	}

	return noteEnc, sourceEnc, nil
}

// openEntry decrypts the encrypted columns into e.
func (s *Store) openEntry(e *model.Entry, valueEnc, noteEnc, sourceEnc []byte) error {
	if s.sealer == nil {
		return errNoSealer
	}

	var err error

	if e.Value, err = s.sealer.Open(valueEnc, seal.AADValue); err != nil {
		return err
	}

	if e.Note, err = s.sealer.Open(noteEnc, seal.AADNote); err != nil {
		return err
	}

	e.Source, err = s.sealer.Open(sourceEnc, seal.AADSource)

	return err
}

// auditView is the form of an entry that goes into audit_logs.detail. The audit
// trail must not carry plaintext back in, so the value is masked and free text
// is replaced by a marker.
func (s *Store) auditView(e model.Entry) model.Entry {
	e.Value = seal.Mask(e.Value)

	if e.Note != "" {
		e.Note = "[encrypted]"
	}

	if e.Source != "" {
		e.Source = "[encrypted]"
	}

	return e
}
