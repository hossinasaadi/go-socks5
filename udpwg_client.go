package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	ProtocolFlagKeepalive = 1 << 0
	ProtocolFlagRebind    = 1 << 1
	ProtocolFlagDNS       = 1 << 2
	ProtocolFlagIPv6      = 1 << 3

	MaxPreambleSize = 23
	MaxPayloadSize  = 32768
	MaxMessageSize  = MaxPreambleSize + MaxPayloadSize
)

type Client struct {
	conn       net.Conn
	sessions   map[uint16]*Session
	writeCh    chan []byte
	closeCh    chan struct{}
	sessMu     sync.RWMutex
	nextConnID uint16
}

type Session struct {
	ConnID     uint16
	RemoteAddr *net.UDPAddr
	OnPacket   func([]byte)
}

// NewClient dials the udpgw server and tunes TCP for lower latency and fewer stalls.
func NewClient(serverAddr string) (*Client, error) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		// Reduce latency spikes due to Nagle/delayed ACK interaction
		_ = tc.SetNoDelay(true)
		// Keep the connection alive through NATs
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		// Larger buffers can help throughput on high-BDP links
		_ = tc.SetReadBuffer(1 << 20)  // 1 MiB
		_ = tc.SetWriteBuffer(1 << 20) // 1 MiB
	}

	c := &Client{
		conn:     conn,
		sessions: make(map[uint16]*Session),
		writeCh:  make(chan []byte, 1024), // buffered writer to avoid writer lock contention
		closeCh:  make(chan struct{}),
	}

	go c.writer()
	go c.readLoop()
	return c, nil
}

func (c *Client) getNextConnID() uint16 {
	c.sessMu.Lock()
	id := c.nextConnID
	c.nextConnID++
	c.sessMu.Unlock()
	return id
}

func (c *Client) AddSession(remote *net.UDPAddr, onPacket func([]byte)) (*Session, error) {
	s := &Session{
		ConnID:     c.getNextConnID(),
		RemoteAddr: remote,
		OnPacket:   onPacket,
	}
	c.sessMu.Lock()
	c.sessions[s.ConnID] = s
	c.sessMu.Unlock()
	return s, nil
}

func (c *Client) RemoveSession(connID uint16) {
	c.sessMu.Lock()
	delete(c.sessions, connID)
	c.sessMu.Unlock()
}

// Send enqueues one UDP packet toward the udpgw server.
func (c *Client) Send(sess *Session, payload []byte, rebind bool, isDNS bool) error {
	if len(payload) > MaxPayloadSize {
		return errors.New("payload too large")
	}

	var flags uint8
	if rebind {
		flags |= ProtocolFlagRebind
	}
	if isDNS {
		flags |= ProtocolFlagDNS
	}

	ip4 := sess.RemoteAddr.IP.To4()
	var preambleSize int
	var ip []byte
	if ip4 == nil {
		flags |= ProtocolFlagIPv6
		preambleSize = 2 + 1 + 2 + 16 + 2
		ip = sess.RemoteAddr.IP
	} else {
		preambleSize = 2 + 1 + 2 + 4 + 2
		ip = ip4
	}

	buf := make([]byte, preambleSize+len(payload))
	// size (excluding the initial 2 bytes)
	size := uint16(preambleSize - 2 + len(payload))
	binary.LittleEndian.PutUint16(buf[0:2], size)
	// flags
	buf[2] = flags
	// connID
	binary.LittleEndian.PutUint16(buf[3:5], sess.ConnID)
	// addr
	off := 5
	copy(buf[off:], ip)
	off += len(ip)
	binary.BigEndian.PutUint16(buf[off:], uint16(sess.RemoteAddr.Port))
	off += 2
	copy(buf[off:], payload)

	select {
	case c.writeCh <- buf:
		return nil
	case <-c.closeCh:
		return errors.New("client closed")
	}
}

// writer serializes all writes to avoid mutex contention and Nagle interactions.
func (c *Client) writer() {
	for {
		select {
		case b := <-c.writeCh:
			// Set a short write deadline to avoid rare indefinite stalls
			_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := c.conn.Write(b)
			if err != nil {
				// Close on write error to unblock readers/senders
				_ = c.conn.Close()
				close(c.closeCh)
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *Client) readLoop() {
	buf := make([]byte, MaxMessageSize)
	for {
		// Size
		if _, err := io.ReadFull(c.conn, buf[:2]); err != nil {
			return
		}
		size := binary.LittleEndian.Uint16(buf[:2])
		if size > MaxMessageSize-2 {
			return
		}
		// Body
		if _, err := io.ReadFull(c.conn, buf[2:2+size]); err != nil {
			return
		}

		flags := buf[2]
		if flags&ProtocolFlagKeepalive != 0 {
			continue
		}
		connID := binary.LittleEndian.Uint16(buf[3:5])
		off := 5
		if flags&ProtocolFlagIPv6 != 0 {
			off += 16
		} else {
			off += 4
		}
		// skip port (we don't use it locally)
		off += 2
		payload := buf[off : 2+size]

		c.sessMu.RLock()
		s, ok := c.sessions[connID]
		c.sessMu.RUnlock()
		if ok && s.OnPacket != nil {
			// Avoid blocking the read loop on slow callbacks
			go s.OnPacket(payload)
		}
	}
}

func (c *Client) SendKeepAlive() error {
	b := []byte{0, 0, ProtocolFlagKeepalive, 0, 0}
	binary.LittleEndian.PutUint16(b[:2], 3)
	select {
	case c.writeCh <- b:
		return nil
	case <-c.closeCh:
		return errors.New("client closed")
	}
}

func (c *Client) Close() error {
	select {
	case <-c.closeCh:
		// already closed
	default:
		close(c.closeCh)
	}
	return c.conn.Close()
}
