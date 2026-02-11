package mtlswhitelist

import "errors"

// UserStore abstracts access to 2FA user data.
// Implementations: configUserStore (inline config), kubernetesUserStore, valkeyUserStore.
type UserStore interface {
	// Type returns the name of the store implementation (config, kubernetes, valkey).
	Type() string
	// ListUsers returns all identity→credential mappings.
	ListUsers() (map[string]interface{}, error)
	// GetUserData returns credentials for a specific identity key.
	GetUserData(key string) (interface{}, bool, error)
	// SetUserData persists credentials for a given identity key.
	SetUserData(key string, value interface{}) error
}

// configUserStore uses the inline twoFactor.users config (read-only).
type configUserStore struct {
	users map[string]interface{}
}

func (s *configUserStore) Type() string { return "config" }

func newConfigUserStore(users map[string]interface{}) *configUserStore {
	if users == nil {
		users = make(map[string]interface{})
	}
	return &configUserStore{users: users}
}

func (s *configUserStore) ListUsers() (map[string]interface{}, error) {
	return s.users, nil
}

func (s *configUserStore) GetUserData(key string) (interface{}, bool, error) {
	val, ok := s.users[key]
	return val, ok, nil
}

func (s *configUserStore) SetUserData(_ string, _ interface{}) error {
	return errors.New("configUserStore is read-only; configure a userStore (kubernetes or valkey) to enable registration")
}
