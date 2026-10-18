package keys

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Client is ftwcloudd's side of the keys socket. One connection carries
// every request; it is dialled on first use and again after it breaks. Safe
// for concurrent use. Requests on one session must not overlap: the caller
// keeps each session's frames in order.
type Client struct {
	dial func() (net.Conn, error)

	mu      sync.Mutex
	conn    net.Conn
	next    uint64
	waiting map[uint64]chan response
	wmu     sync.Mutex
}

// Dial is a client for the socket at path. Nothing connects until the first
// request.
func Dial(path string) *Client {
	return newClient(func() (net.Conn, error) {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return d.DialContext(ctx, "unix", path)
	})
}

func newClient(dial func() (net.Conn, error)) *Client {
	return &Client{dial: dial, waiting: map[uint64]chan response{}}
}

// ErrUnavailable is a keys part that cannot be reached.
var ErrUnavailable = errors.New("keys: not reachable")

func (c *Client) call(ctx context.Context, req request) (response, error) {
	c.mu.Lock()
	if c.conn == nil {
		conn, err := c.dial()
		if err != nil {
			c.mu.Unlock()
			return response{}, ErrUnavailable
		}
		c.conn = conn
		go c.read(conn)
	}
	conn := c.conn
	c.next++
	req.ID = c.next
	ch := make(chan response, 1)
	c.waiting[req.ID] = ch
	c.mu.Unlock()

	c.wmu.Lock()
	err := writeFrame(conn, req)
	c.wmu.Unlock()
	if err != nil {
		c.drop(conn)
		return response{}, ErrUnavailable
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return response{}, ErrUnavailable
		}
		return resp, errorFrom(resp.Err)
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.waiting, req.ID)
		c.mu.Unlock()
		return response{}, ctx.Err()
	}
}

func (c *Client) read(conn net.Conn) {
	for {
		var resp response
		if err := readFrame(conn, &resp); err != nil {
			c.drop(conn)
			return
		}
		c.mu.Lock()
		ch := c.waiting[resp.ID]
		delete(c.waiting, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
}

// drop forgets a broken connection and fails everything waiting on it.
func (c *Client) drop(conn net.Conn) {
	_ = conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	c.conn = nil
	for id, ch := range c.waiting {
		close(ch)
		delete(c.waiting, id)
	}
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		c.drop(conn)
	}
	return nil
}

// New makes an agent key pair and returns its id and public half. The
// private half stays sealed in the keys part. Until Keep, it opens no
// session, and it is deleted within PendingFor.
func (c *Client) New(ctx context.Context) (kid string, pub []byte, err error) {
	resp, err := c.call(ctx, request{Op: opNew})
	return resp.Kid, resp.Pub, err
}

// Keep keeps a key whose agent the owner approved.
func (c *Client) Keep(ctx context.Context, kid string) error {
	_, err := c.call(ctx, request{Op: opKeep, Kid: kid})
	return err
}

// Forget deletes a key and ends its sessions.
func (c *Client) Forget(ctx context.Context, kid string) error {
	_, err := c.call(ctx, request{Op: opForget, Kid: kid})
	return err
}

// Open starts a session from agent key kid to the box whose Noise static key
// is boxStatic, and returns its id and handshake message 1.
func (c *Client) Open(ctx context.Context, kid string, boxStatic []byte) (sess string, msg1 []byte, err error) {
	resp, err := c.call(ctx, request{Op: opOpen, Kid: kid, RS: boxStatic})
	return resp.Sess, resp.D, err
}

// Finish reads the box's handshake message 2. The session is then ready.
func (c *Client) Finish(ctx context.Context, sess string, msg2 []byte) error {
	_, err := c.call(ctx, request{Op: opFinish, Sess: sess, D: msg2})
	return err
}

// Seal encrypts one frame of the session for the box.
func (c *Client) Seal(ctx context.Context, sess string, frame []byte) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opSeal, Sess: sess, D: frame})
	return resp.D, err
}

// Unseal decrypts one message from the box.
func (c *Client) Unseal(ctx context.Context, sess string, msg []byte) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opUnseal, Sess: sess, D: msg})
	return resp.D, err
}

// End closes a session.
func (c *Client) End(ctx context.Context, sess string) error {
	_, err := c.call(ctx, request{Op: opClose, Sess: sess})
	return err
}

// OpenInvite opens a pending key only for a typed agent invitation claim.
// It grants no ordinary session until Core claims it and its roster arrives.
func (c *Client) OpenInvite(ctx context.Context, kid string, boxStatic, payload []byte) (string, []byte, error) {
	resp, err := c.call(ctx, request{Op: opOpenInvite, Kid: kid, RS: boxStatic, D: payload})
	return resp.Sess, resp.D, err
}
