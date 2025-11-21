package backend

// Backend is the interface for a secrets backend
type Backend interface {
	GetSecret(mountPath, secretPath string) (map[string]interface{}, error)
	PutSecret(mountPath, secretPath string, data map[string]interface{}) error
	DeleteSecret(mountPath, secretPath string) error
	TaintSecret(mountPath, secretPath string) error
	UntaintSecret(mountPath, secretPath string) error
	Ping() error
	GetType() string
}
