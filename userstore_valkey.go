package mtlswhitelist

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	valkeyDefaultPort   = "6379"
	valkeyDialTimeout   = 5 * time.Second
	valkeyReadTimeout   = 5 * time.Second
	valkeyWriteTimeout  = 5 * time.Second
	valkeyCacheTTL      = 10 * time.Second
	valkeyDefaultPrefix = "2fa:"
)

// valkeyUserStore stores 2FA user data in Valkey/Redis.
// Each user is stored as a key: "{prefix}{identity}" with a JSON value.
type valkeyUserStore struct {
	address   string
	password  string
	db        int
	keyPrefix string

	mu        sync.RWMutex
	cache     map[string]interface{}
	cacheTime time.Time
}

func (s *valkeyUserStore) Type() string { return "valkey" }

func newValkeyUserStore(address, password string, db int, keyPrefix string) (*valkeyUserStore, error) {
	if address == "" {
		return nil, errors.New("valkey address is required")
	}
	if !strings.Contains(address, ":") {
		address = address + ":" + valkeyDefaultPort
	}
	if keyPrefix == "" {
		keyPrefix = valkeyDefaultPrefix
	}

	store := &valkeyUserStore{
		address:   address,
		password:  password,
		db:        db,
		keyPrefix: keyPrefix,
	}

	// Verify connectivity
	conn, err := store.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to valkey at %s: %w", address, err)
	}
	_ = conn.Close()

	return store, nil
}

func (s *valkeyUserStore) connect() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", s.address, valkeyDialTimeout)
	if err != nil {
		return nil, err
	}

	if s.password != "" {
		if err := s.execSimple(conn, "AUTH", s.password); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("AUTH failed: %w", err)
		}
	}

	if s.db > 0 {
		if err := s.execSimple(conn, "SELECT", strconv.Itoa(s.db)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("SELECT failed: %w", err)
		}
	}

	return conn, nil
}

// execSimple sends a command and expects a +OK response.
func (s *valkeyUserStore) execSimple(conn net.Conn, args ...string) error {
	if err := s.writeCommand(conn, args...); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(valkeyReadTimeout))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "+") {
		return fmt.Errorf("unexpected response: %s", line)
	}
	return nil
}

// writeCommand writes a RESP array command.
func (s *valkeyUserStore) writeCommand(conn net.Conn, args ...string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(valkeyWriteTimeout))
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, arg := range args {
		buf.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg))
	}
	_, err := io.WriteString(conn, buf.String())
	return err
}

// readRESP reads a single RESP response value.
func (s *valkeyUserStore) readRESP(reader *bufio.Reader) (interface{}, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("empty RESP response")
	}

	switch line[0] {
	case '+': // Simple string
		return line[1:], nil
	case '-': // Error
		return nil, fmt.Errorf("RESP error: %s", line[1:])
	case ':': // Integer
		n, parseErr := strconv.ParseInt(line[1:], 10, 64)
		return n, parseErr
	case '$': // Bulk string
		return s.readBulkString(reader, line)
	case '*': // Array
		return s.readArray(reader, line)
	default:
		return nil, fmt.Errorf("unknown RESP type: %c", line[0])
	}
}

func (s *valkeyUserStore) readBulkString(reader *bufio.Reader, line string) (interface{}, error) {
	size, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	if size == -1 {
		return nil, nil //nolint:nilnil // nil = key not found in Redis
	}
	const crlfLen = 2
	buf := make([]byte, size+crlfLen)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return nil, err
	}
	return string(buf[:size]), nil
}

func (s *valkeyUserStore) readArray(reader *bufio.Reader, line string) (interface{}, error) {
	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	if count == -1 {
		return nil, nil //nolint:nilnil
	}
	arr := make([]interface{}, count)
	for i := 0; i < count; i++ {
		arr[i], err = s.readRESP(reader)
		if err != nil {
			return nil, err
		}
	}
	return arr, nil
}

// execGet performs GET and returns the string value or empty.
func (s *valkeyUserStore) execGet(key string) (string, bool, error) {
	conn, err := s.connect()
	if err != nil {
		return "", false, err
	}
	defer func() { _ = conn.Close() }()

	if writeErr := s.writeCommand(conn, "GET", key); writeErr != nil {
		return "", false, writeErr
	}
	_ = conn.SetReadDeadline(time.Now().Add(valkeyReadTimeout))
	reader := bufio.NewReader(conn)
	val, readErr := s.readRESP(reader)
	if readErr != nil {
		return "", false, readErr
	}
	if val == nil {
		return "", false, nil
	}
	str, ok := val.(string)
	return str, ok, nil
}

// execSet performs SET key value.
func (s *valkeyUserStore) execSet(key, value string) error {
	conn, err := s.connect()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if writeErr := s.writeCommand(conn, "SET", key, value); writeErr != nil {
		return writeErr
	}
	_ = conn.SetReadDeadline(time.Now().Add(valkeyReadTimeout))
	reader := bufio.NewReader(conn)
	val, readErr := s.readRESP(reader)
	if readErr != nil {
		return readErr
	}
	if str, ok := val.(string); ok && str == "OK" {
		return nil
	}
	return fmt.Errorf("unexpected SET response: %v", val)
}

// execKeys performs KEYS pattern and returns matching keys.
func (s *valkeyUserStore) execKeys(pattern string) ([]string, error) {
	conn, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if writeErr := s.writeCommand(conn, "KEYS", pattern); writeErr != nil {
		return nil, writeErr
	}
	_ = conn.SetReadDeadline(time.Now().Add(valkeyReadTimeout))
	reader := bufio.NewReader(conn)
	val, readErr := s.readRESP(reader)
	if readErr != nil {
		return nil, readErr
	}
	if val == nil {
		return nil, nil
	}
	arr, ok := val.([]interface{})
	if !ok {
		return nil, errors.New("unexpected KEYS response type")
	}
	keys := make([]string, 0, len(arr))
	for _, item := range arr {
		if str, ok := item.(string); ok {
			keys = append(keys, str)
		}
	}
	return keys, nil
}

func (s *valkeyUserStore) fetchAll() (map[string]interface{}, error) {
	s.mu.RLock()
	if s.cache != nil && time.Since(s.cacheTime) < valkeyCacheTTL {
		cached := s.cache
		s.mu.RUnlock()
		return cached, nil
	}
	s.mu.RUnlock()

	keys, err := s.execKeys(s.keyPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	users := make(map[string]interface{}, len(keys))
	for _, fullKey := range keys {
		identity := strings.TrimPrefix(fullKey, s.keyPrefix)
		val, ok, err := s.execGet(fullKey)
		if err != nil || !ok {
			continue
		}
		var userData interface{}
		if err := json.Unmarshal([]byte(val), &userData); err != nil {
			users[identity] = val
			continue
		}
		users[identity] = userData
	}

	s.mu.Lock()
	s.cache = users
	s.cacheTime = time.Now()
	s.mu.Unlock()

	return users, nil
}

func (s *valkeyUserStore) ListUsers() (map[string]interface{}, error) {
	if s == nil {
		return nil, errors.New("valkey store not initialized")
	}
	return s.fetchAll()
}

func (s *valkeyUserStore) GetUserData(key string) (interface{}, bool, error) {
	if s == nil {
		return nil, false, errors.New("valkey store not initialized")
	}
	fullKey := s.keyPrefix + key
	val, ok, err := s.execGet(fullKey)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	var userData interface{}
	if unmarshalErr := json.Unmarshal([]byte(val), &userData); unmarshalErr != nil {
		return val, true, nil //nolint:nilerr // if not JSON, return as plain string
	}
	return userData, true, nil
}

func (s *valkeyUserStore) SetUserData(key string, value interface{}) error {
	if s == nil {
		return errors.New("valkey store not initialized")
	}
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	fullKey := s.keyPrefix + key
	if err := s.execSet(fullKey, string(jsonBytes)); err != nil {
		return fmt.Errorf("failed to SET: %w", err)
	}

	// Invalidate cache
	s.mu.Lock()
	s.cache = nil
	s.mu.Unlock()

	return nil
}
