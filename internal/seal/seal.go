// Package seal bảo vệ dữ liệu blacklist ở trạng thái lưu trữ (data at rest).
//
//   - Seal/Open: Dùng AES-256-GCM để kẻ trộm dù có bản dump database cũng không đọc được giá trị thật.
//   - Blind: Dùng HMAC-SHA256 kèm bí mật pepper để các hàng vẫn có thể so sánh bằng (checker chỉ so sánh bằng)
//     mà kẻ xấu không thể brute-force dò ngược lại số điện thoại từ index đã lưu.
//
// Cả hai khóa đều được dẫn xuất bằng HKDF từ hai bí mật riêng biệt (DATA_KEY, DATA_PEPPER),
// do đó việc lộ một khóa sẽ không làm ảnh hưởng đến khóa còn lại.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/hkdf"
)

const minSecretLen = 32

// Nhãn tên cột được dùng làm AAD (Additional Authenticated Data) để gắn chặt ciphertext với đúng cột của nó,
// ngăn kẻ tấn công có quyền ghi tráo đổi giá trị giữa cột note_enc và value_enc.
const (
	AADValue  = "value"
	AADNote   = "note"
	AADSource = "source"
)

// Sealer: Cấu trúc quản lý mã hóa/giải mã và tạo chỉ mục tìm kiếm ẩn danh.
type Sealer struct {
	aead    cipher.AEAD           // Khóa hiện tại: dùng cho Seal và Open mặc định
	aeads   map[int16]cipher.AEAD // Tất cả các khóa theo phiên bản, bao gồm cả khóa hiện tại
	pepper  []byte
	version int16
}

// ErrUnknownKeyVersion báo hiệu bản ghi được mã hóa bằng phiên bản khóa chưa được cấu hình.
var ErrUnknownKeyVersion = errors.New("key version is not configured")

// Option: Hàm cấu hình tùy chọn cho New.
type Option func(*options)

type options struct{ retired map[int16]string }

// WithRetiredKeys: Thêm danh sách các khóa cũ đã ngừng dùng để vẫn giải mã được dữ liệu quá khứ (Key Rotation).
func WithRetiredKeys(keys map[int16]string) Option { return func(o *options) { o.retired = keys } }

// aeadFor: Dẫn xuất khóa và khởi tạo bộ giải/mã hóa AES-256-GCM từ một chuỗi secret cụ thể.
func aeadFor(secret string) (cipher.AEAD, error) {
	encKey, err := derive(secret, "vsf-data-encryption-v1")
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// New: Khởi tạo Sealer quản lý mã hóa dữ liệu với khóa hiện tại, các khóa cũ (nếu có) và blind-index pepper.
func New(dataKey, pepper string, version int16, opts ...Option) (*Sealer, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	if len(dataKey) < minSecretLen || len(pepper) < minSecretLen {
		return nil, fmt.Errorf("DATA_KEY và DATA_PEPPER mỗi khóa phải có ít nhất %d ký tự", minSecretLen)
	}

	if dataKey == pepper {
		return nil, errors.New("DATA_KEY và DATA_PEPPER phải là hai chuỗi bí mật khác nhau")
	}

	if version < 1 {
		return nil, fmt.Errorf("DATA_KEY_VERSION phải lớn hơn hoặc bằng 1, nhận được %d", version)
	}

	blindKey, err := derive(pepper, "vsf-blind-index-v1")
	if err != nil {
		return nil, err
	}

	current, err := aeadFor(dataKey)
	if err != nil {
		return nil, err
	}

	aeads := map[int16]cipher.AEAD{version: current}
	seen := map[string]int16{dataKey: version}

	// Sắp xếp phiên bản để thứ tự kiểm tra lỗi luôn nhất quán
	versions := make([]int16, 0, len(o.retired))
	for v := range o.retired {
		versions = append(versions, v)
	}

	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	for _, v := range versions {
		secret := o.retired[v]

		switch {
		case v < 1:
			return nil, fmt.Errorf("DATA_KEY_V%d: phiên bản khóa phải bắt đầu từ 1", v)

		case v == version:
			return nil, fmt.Errorf("DATA_KEY_V%d trùng với phiên bản hiện tại (DATA_KEY_VERSION): hãy chỉ dùng DATA_KEY", v)

		case len(secret) < minSecretLen:
			return nil, fmt.Errorf("DATA_KEY_V%d phải có ít nhất %d ký tự", v, minSecretLen)

		case secret == pepper:
			return nil, fmt.Errorf("DATA_KEY_V%d phải khác với DATA_PEPPER", v)
		}

		if other, dup := seen[secret]; dup {
			return nil, fmt.Errorf("DATA_KEY_V%d có cùng secret với phiên bản %d: mỗi phiên bản cần một khóa riêng", v, other)
		}

		seen[secret] = v

		a, err := aeadFor(secret)
		if err != nil {
			return nil, err
		}

		aeads[v] = a
	}

	return &Sealer{aead: current, aeads: aeads, pepper: blindKey, version: version}, nil
}

// derive: Dẫn xuất khóa 32 bytes an toàn từ secret gốc bằng thuật toán HKDF-SHA256.
func derive(secret, info string) ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(info)), out); err != nil {
		return nil, err
	}

	return out, nil
}

// Version: Trả về phiên bản hiện tại của khóa mã hóa.
func (s *Sealer) Version() int16 { return s.version }

// Versions: Liệt kê tất cả các phiên bản khóa đã được cấu hình theo thứ tự tăng dần.
func (s *Sealer) Versions() []int16 {
	out := make([]int16, 0, len(s.aeads))
	for v := range s.aeads {
		out = append(out, v)
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out
}

// HasVersion: Kiểm tra xem hệ thống có cấu hình khóa cho phiên bản chỉ định hay không.
func (s *Sealer) HasVersion(version int16) bool {
	_, ok := s.aeads[version]
	return ok
}

// Seal: Mã hóa chuỗi dữ liệu rõ bằng AES-256-GCM với Nonce ngẫu nhiên 12 bytes và dữ liệu xác thực AAD.
func (s *Sealer) Seal(plaintext, aad string) ([]byte, error) {
	// Khai báo slice byte với độ dài 12 bytes chuẩn NIST cho Nonce
	nonce := make([]byte, s.aead.NonceSize())
	// Nạp dữ liệu ngẫu nhiên bảo mật từ crypto/rand
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Nối Nonce (12 bytes) + Ciphertext + Auth Tag (16 bytes)
	return s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad)), nil
}

// Open: Giải mã dữ liệu bằng DUY NHẤT khóa phiên bản hiện tại (dùng cho Redis cache, dữ liệu tạm).
func (s *Sealer) Open(blob []byte, aad string) (string, error) {
	return openWith(s.aead, blob, aad)
}

// OpenVersion: Giải mã dữ liệu dựa theo đúng phiên bản khóa đã lưu trong cơ sở dữ liệu.
func (s *Sealer) OpenVersion(version int16, blob []byte, aad string) (string, error) {
	a, ok := s.aeads[version]
	if !ok {
		return "", fmt.Errorf("%w: %d (hãy thiết lập DATA_KEY_V%d tương ứng với khóa đã mã hóa dữ liệu này)", ErrUnknownKeyVersion, version, version)
	}

	return openWith(a, blob, aad)
}

// openWith: Hàm trợ giúp bóc tách 12 byte Nonce và giải mã payload bằng AEAD tương ứng.
func openWith(aead cipher.AEAD, blob []byte, aad string) (string, error) {
	n := aead.NonceSize() // Lấy độ dài Nonce chuẩn (12 bytes)
	if len(blob) < n+aead.Overhead() {
		return "", errors.New("ciphertext too short")
	}

	pt, err := aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(pt), nil
}

// Blind: Tạo chỉ mục tìm kiếm ẩn danh (blind index) bằng HMAC-SHA256 kèm pepper bí mật.
func (s *Sealer) Blind(typ, matchType, value string) []byte {
	m := hmac.New(sha256.New, s.pepper)

	for _, p := range []string{typ, matchType, value} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}

	return m.Sum(nil)
}

// Hash64: Lấy 8 byte đầu của blind index để tạo số nguyên 64-bit dùng cho partition DB và Bloom filter.
func Hash64(blind []byte) int64 {
	return int64(binary.BigEndian.Uint64(blind[:8]))  // #nosec G115 -- chủ ý: lấy 8 byte của HMAC làm hash; chỉ đổi cách đọc bit, không phải phép tính số học
}

// Mask: Che bớt các ký tự nhạy cảm trong chuỗi (giữ 3 ký tự đầu và 2 ký tự cuối) để hiển thị an toàn.
func Mask(v string) string {
	r := []rune(v)

	if len(r) <= 6 {
		if len(r) == 0 {
			return ""
		}

		return string(r[:1]) + "***"
	}

	return string(r[:3]) + "***" + string(r[len(r)-2:])
}

// Hasher: Chuyển đổi Sealer thành hàm băm tương thích với interface của normalize.SetHasher.
func (s *Sealer) Hasher() func(typ, matchType, value string) (int64, []byte) {
	return func(typ, matchType, value string) (int64, []byte) {
		b := s.Blind(typ, matchType, value)
		return Hash64(b), b
	}
}
