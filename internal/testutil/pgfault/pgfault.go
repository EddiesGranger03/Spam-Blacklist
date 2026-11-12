// Package pgfault là một proxy TCP tới PostgreSQL dùng CHO TEST, để mô phỏng một cách tất định việc mất kết nối giữa hai
// câu lệnh hoặc giữa lúc đang nhận dữ liệu. Không gói production nào import nó.
//
// Proxy hiểu vừa đủ giao thức PostgreSQL (khung thông điệp phía client: 1 byte loại, 4 byte độ dài) để đếm các
// "vòng đi về" (round trip): mỗi thông điệp Sync (kết thúc một câu lệnh theo giao thức mở rộng) hoặc Query (câu lệnh
// đơn giản) là một vòng. FailAtRoundTrip(n) làm đứt MỌI kết nối ngay trước khi vòng thứ n được chuyển cho server, nên
// server thấy kết nối đóng giữa chừng (giao dịch đang mở bị hủy) còn client nhận lỗi mạng. Quét n = 1, 2, 3, ... cho đến
// khi thao tác chạy xong thì phủ được MỌI ranh giới giữa hai câu lệnh của thao tác đó.
//
// Chỉ dùng được với sslmode=disable (không giải mã TLS).
package pgfault

import (
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

// Proxy chuyển tiếp các kết nối tới target và có thể làm đứt chúng theo yêu cầu.
type Proxy struct {
	ln     net.Listener
	target string

	mu    sync.Mutex
	conns map[net.Conn]struct{}

	roundTrips atomic.Int64
	failAt     atomic.Int64 // 0 = tắt: đứt TRƯỚC khi chuyển vòng thứ failAt
	afterAt    atomic.Int64 // 0 = tắt: chuyển vòng thứ afterAt cho server rồi đứt, client không nhận được phản hồi
	serverCut  atomic.Int64 // đứt khi server đã gửi quá chừng này byte cho client (từ lúc đặt); 0 = tắt
	serverSent atomic.Int64
	cuts       atomic.Int64
}

// Start mở proxy ở một cổng ngẫu nhiên trên 127.0.0.1, chuyển tiếp tới target (host:port); tự đóng khi test xong.
func Start(t testing.TB, target string) *Proxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	p := &Proxy{ln: ln, target: target, conns: map[net.Conn]struct{}{}}

	go p.accept()

	t.Cleanup(func() {
		_ = ln.Close()
		p.Cut()
	})

	return p
}

// DSN trả về DSN giống base nhưng đi qua proxy.
func (p *Proxy) DSN(t testing.TB, base string) string {
	t.Helper()

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	u.Host = p.ln.Addr().String()

	return u.String()
}

// TargetOf trả host:port của một DSN, để truyền cho Start.
func TargetOf(t testing.TB, dsn string) string {
	t.Helper()

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}

	return u.Host
}

// FailAtRoundTrip đặt lại bộ đếm và làm đứt mọi kết nối ngay trước vòng đi về thứ n (n >= 1) tính từ lúc gọi.
func (p *Proxy) FailAtRoundTrip(n int) {
	p.roundTrips.Store(0)
	p.failAt.Store(int64(n))
}

// FailAfterRoundTrip chuyển vòng đi về thứ n (n >= 1) cho server, rồi làm đứt kết nối đó NGAY: server vẫn xử lý trọn vòng
// này (nếu là COMMIT thì giao dịch đã được lưu) nhưng client không bao giờ nhận được phản hồi. Đây là tình huống khó nhất:
// thao tác báo lỗi dù dữ liệu đã được ghi. Kết nối được đóng nửa chiều (FIN, không RST) để server không bỏ dở dữ liệu đã nhận.
func (p *Proxy) FailAfterRoundTrip(n int) {
	p.roundTrips.Store(0)
	p.failAt.Store(0)
	p.afterAt.Store(int64(n))
}

// FailAfterServerBytes làm đứt mọi kết nối khi server đã gửi tổng cộng hơn n byte cho client kể từ lúc gọi
// (mô phỏng mất kết nối GIỮA LÚC đang nhận một kết quả lớn).
func (p *Proxy) FailAfterServerBytes(n int) {
	p.serverSent.Store(0)
	p.serverCut.Store(int64(n))
}

// ServerBytes là tổng số byte server đã gửi cho client kể từ lần FailAfterServerBytes gần nhất; để đo kích thước một kết quả
// trước (gọi FailAfterServerBytes với số rất lớn), rồi đặt ngưỡng đứt ở giữa.
func (p *Proxy) ServerBytes() int { return int(p.serverSent.Load()) }

// Heal tắt mọi lỗi đã đặt; proxy tiếp tục chuyển tiếp bình thường. Các kết nối đã bị đứt không tự sống lại.
func (p *Proxy) Heal() {
	p.failAt.Store(0)
	p.afterAt.Store(0)
	p.serverCut.Store(0)
}

// RoundTrips là số vòng đi về đã thấy kể từ lần FailAtRoundTrip gần nhất.
func (p *Proxy) RoundTrips() int { return int(p.roundTrips.Load()) }

// Cuts là số lần proxy đã làm đứt kết nối (kể cả lần gọi Cut trực tiếp).
func (p *Proxy) Cuts() int { return int(p.cuts.Load()) }

// Cut làm đứt mọi kết nối đang mở ngay bây giờ.
func (p *Proxy) Cut() {
	p.cuts.Add(1)

	p.mu.Lock()
	defer p.mu.Unlock()

	for c := range p.conns {
		_ = c.Close()
	}
}

func (p *Proxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *Proxy) accept() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}

		server, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}

		p.track(client)
		p.track(server)

		go p.pipeServerToClient(server, client)
		go p.pipeClientToServer(client, server)
	}
}

func (p *Proxy) pipeServerToClient(server, client net.Conn) {
	defer client.Close()
	defer server.Close()

	buf := make([]byte, 8192)

	for {
		n, err := server.Read(buf)
		if n > 0 {
			sent := p.serverSent.Add(int64(n))

			if limit := p.serverCut.Load(); limit > 0 && sent > limit {
				p.Cut()
				return
			}

			if _, werr := client.Write(buf[:n]); werr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

func (p *Proxy) pipeClientToServer(client, server net.Conn) {
	// Ở chế độ "đứt sau", để pipeServerToClient tự đóng server khi đã đọc hết phản hồi (tránh RST làm server bỏ dữ liệu).
	keepServer := false

	defer client.Close()
	defer func() {
		if !keepServer {
			server.Close()
		}
	}()

	// Thông điệp khởi động không có byte loại: 4 byte độ dài (gồm chính nó) rồi nội dung.
	var head [4]byte
	if _, err := io.ReadFull(client, head[:]); err != nil {
		return
	}

	size := int(binary.BigEndian.Uint32(head[:]))
	if size < 4 || size > 1<<20 {
		return
	}

	startup := make([]byte, size)
	copy(startup, head[:])

	if _, err := io.ReadFull(client, startup[4:]); err != nil {
		return
	}

	if _, err := server.Write(startup); err != nil {
		return
	}

	// Từ đây mọi thông điệp có dạng: 1 byte loại, 4 byte độ dài (gồm chính nó), nội dung.
	for {
		var h [5]byte
		if _, err := io.ReadFull(client, h[:]); err != nil {
			return
		}

		n := int(binary.BigEndian.Uint32(h[1:]))
		if n < 4 || n > 1<<30 {
			return
		}

		msg := make([]byte, 1+n)
		copy(msg, h[:])

		if _, err := io.ReadFull(client, msg[5:]); err != nil {
			return
		}

		if h[0] == 'S' || h[0] == 'Q' {
			count := p.roundTrips.Add(1)

			if at := p.failAt.Load(); at > 0 && count >= at {
				p.Cut() // đứt TRƯỚC khi chuyển vòng này cho server

				return
			}
		}

		if _, err := server.Write(msg); err != nil {
			return
		}

		if (h[0] == 'S' || h[0] == 'Q') && p.afterAt.Load() > 0 && p.roundTrips.Load() >= p.afterAt.Load() {
			p.cuts.Add(1)

			if tcp, ok := server.(*net.TCPConn); ok {
				_ = tcp.CloseWrite() // FIN: server xử lý hết dữ liệu đã nhận rồi mới thấy EOF
				keepServer = true
			}

			return // defer đóng phía client: client mất kết nối và không nhận được phản hồi
		}
	}
}
