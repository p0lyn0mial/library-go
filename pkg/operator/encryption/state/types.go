package state

import (
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

// These annotations try to scare anyone away from editing the encryption secrets.  It is trivial for
// an external actor to break the invariants of the state machine and render the cluster unrecoverable.
const (
	KubernetesDescriptionKey        = "kubernetes.io/description"
	KubernetesDescriptionScaryValue = `WARNING: DO NOT EDIT.
Altering of the encryption secrets will render you cluster inaccessible.
Catastrophic data loss can occur from the most minor changes.`
)

// GroupResourceState represents, for a single group resource, the write and read keys in a
// format that can be directly translated to and from the on disk EncryptionConfiguration object.
type GroupResourceState struct {
	// the write key of the group resource.
	WriteKey KeyState
	// all read keys of the group resource. Potentially includes the write key.
	ReadKeys []KeyState
}

func (k GroupResourceState) HasWriteKey() bool {
	return len(k.WriteKey.Key.Name) > 0 && len(k.WriteKey.Key.Secret) > 0
}

type KeyState struct {
	Key  apiserverconfigv1.Key
	Mode Mode

	// described whether it is backed by a secret.
	Backed   bool
	Migrated MigrationState
	// some controller logic caused this secret to be created by the key controller.
	InternalReason string
	// the user via unsupportConfigOverrides.encryption.reason triggered this key.
	ExternalReason string
	// stores all the KMS encryption mode related configurations
	KMS *KMSState
}

func (k *KeyState) HasKMSEncryption() bool {
	return k != nil && k.KMS != nil && k.KMS.Encryption != nil
}

func (k *KeyState) HasKMSPlugin() bool {
	return k != nil && k.KMS != nil && k.KMS.Plugin != (configv1.KMSPluginConfig{})
}

func (k *KeyState) HasKMSSecretData() bool {
	return k != nil && k.KMS != nil && len(k.KMS.PluginSecretData.Get()) > 0
}

// KMSState stores all KMS encryption mode related configurations
type KMSState struct {
	// Encoded EncryptionConfig that stores the KMS related fields
	Encryption *apiserverconfigv1.KMSConfiguration

	// Plugin stores KMS plugin specific configurations
	Plugin configv1.KMSPluginConfig

	// PluginSecretData stores data key-value pairs fetched from referenced secrets.
	PluginSecretData KMSSecretData
}

// KMSSecretData stores data key-value pairs fetched from referenced secrets.
// Entries maps secret names to their data key-value pairs.
type KMSSecretData struct {
	Entries map[string]map[string][]byte
}

func (d *KMSSecretData) Get() map[string]map[string][]byte {
	if d.Entries == nil {
		return map[string]map[string][]byte{}
	}
	return d.Entries
}

func (d *KMSSecretData) Set(secretName, dataKey string, value []byte) {
	if d.Entries == nil {
		d.Entries = map[string]map[string][]byte{}
	}
	if d.Entries[secretName] == nil {
		d.Entries[secretName] = map[string][]byte{}
	}
	d.Entries[secretName][dataKey] = value
}

type MigrationState struct {
	// the timestamp fo the last migration
	Timestamp time.Time
	// the resources that were migrated at some point in time to this key.
	Resources []schema.GroupResource
}

// Mode is the value associated with the encryptionSecretMode annotation
type Mode string

// The current set of modes that are supported along with the default Mode that is used.
// These values are encoded into the secret and thus must not be changed.
// Strings are used over iota because they are easier for a human to understand.
const (
	AESCBC    Mode = "aescbc" // available from the first release, see defaultMode below
	AESGCM    Mode = "aesgcm"
	SecretBox Mode = "secretbox" // available from the first release, see defaultMode below
	Identity  Mode = "identity"  // available from the first release, see defaultMode below
	KMS       Mode = "KMS"       // only supports KMS v2

	// Changing this value requires caution to not break downgrades.
	// Specifically, if some new Mode is released in version X, that new Mode cannot
	// be used as the defaultMode until version X+1.  Thus on a downgrade the operator
	// from version X will still be able to honor the observed encryption state
	// (and it will do a key rotation to force the use of the old defaultMode).
	DefaultMode = Identity // we default to encryption being disabled for now
)
