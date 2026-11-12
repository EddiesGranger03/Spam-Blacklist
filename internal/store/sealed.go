package store

import (
	"errors"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

var errNoSealer = errors.New("store: encryption keys are not configured (set DATA_KEY and DATA_PEPPER)")

// SetSealer bật mã hóa dữ liệu lưu trữ. Hàm cũng cài hàm băm có khóa vào
// gói normalize, để khóa tra cứu là HMAC và khớp với dữ liệu đã lưu.
// Phải gọi trước Migrate và trước khi đọc hoặc ghi bất kỳ entry nào.
func (s *Store) SetSealer(sl *seal.Sealer) {
	s.sealer = sl
	normalize.SetHasher(sl.Hasher())
}

// sealNoteSource mã hóa hai cột văn bản tự do của một entry.
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

// openEntry giải mã các cột đã mã hóa vào e. version là key_version của dòng: nó chọn khóa, nên các dòng
// được mã hóa trước một lần xoay khóa vẫn đọc được miễn khóa đó còn được cấu hình (DATA_KEY_V<n>).
func (s *Store) openEntry(e *model.Entry, version int16, valueEnc, noteEnc, sourceEnc []byte) error {
	if s.sealer == nil {
		return errNoSealer
	}

	var err error

	if e.Value, err = s.sealer.OpenVersion(version, valueEnc, seal.AADValue); err != nil {
		return err
	}

	if e.Note, err = s.sealer.OpenVersion(version, noteEnc, seal.AADNote); err != nil {
		return err
	}

	e.Source, err = s.sealer.OpenVersion(version, sourceEnc, seal.AADSource)

	return err
}

// auditView là dạng của entry sẽ đi vào audit_logs.detail. Nhật ký audit không được chứa lại bản rõ,
// nên giá trị bị che và văn bản tự do được thay bằng một dấu đánh dấu.
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
