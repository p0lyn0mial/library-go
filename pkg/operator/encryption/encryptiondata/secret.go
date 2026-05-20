package encryptiondata

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encoding"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const (
	// EncryptionConfSecretName is the name of the final encryption config secret that is revisioned per apiserver rollout.
	EncryptionConfSecretName = "encryption-config"
	// EncryptionConfSecretKey is the map data key used to store the raw bytes of the final encryption config.
	EncryptionConfSecretKey = "encryption-config"
	// encryptionConfigSecretDataPrefix is the data key prefix for KMS plugin secret
	// data entries in the encryption-config Secret. Full key: "kms-plugin-secret-{secretName}_{dataKey}-{keyID}".
	encryptionConfigSecretDataPrefix = "kms-plugin-secret-"
)

func FromSecret(encryptionConfigSecret *corev1.Secret) (*Config, error) {
	data, ok := encryptionConfigSecret.Data[EncryptionConfSecretKey]
	if !ok {
		return nil, nil
	}
	encryptionConfig, err := encoding.DecodeEncryptionConfiguration(data)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Encryption: encryptionConfig}
	if err := cfg.readKMSDataFrom(encryptionConfigSecret.Data); err != nil {
		return nil, err
	}
	return cfg, nil
}

func ToSecret(ns, name string, secretData *Config) (*corev1.Secret, error) {
	if !secretData.HasEncryptionConfiguration() {
		return nil, fmt.Errorf("secret %s/%s has no encryption config", ns, name)
	}

	rawEncryptionCfg, err := encoding.EncodeEncryptionConfiguration(secretData.Encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the encryption config: %v", err)
	}

	s := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Annotations: map[string]string{
				state.KubernetesDescriptionKey: state.KubernetesDescriptionScaryValue,
			},
			Finalizers: []string{"encryption.apiserver.operator.openshift.io/deletion-protection"},
		},
		Data: map[string][]byte{
			EncryptionConfSecretName: rawEncryptionCfg,
		},
		Type: corev1.SecretTypeOpaque,
	}

	if err := secretData.writeKMSDataTo(s.Data); err != nil {
		return nil, err
	}

	return s, nil
}

// ExtractUniqueAndSortedKMSConfigurations collects deduplicated KMS providers from the
// EncryptionConfiguration, strips the resource suffix from each Name, and returns them
// sorted by keyID descending. Duplicate keyIDs with mismatched config (ignoring Name) error out.
func ExtractUniqueAndSortedKMSConfigurations(secretData *Config) ([]*apiserverconfigv1.KMSConfiguration, error) {
	if !secretData.HasEncryptionConfiguration() {
		return nil, fmt.Errorf("encryption configuration is required")
	}
	byKeyID := map[string]*apiserverconfigv1.KMSConfiguration{}
	for _, resource := range secretData.Encryption.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS == nil {
				continue
			}
			keyID, err := getKeyIDFromPluginName(provider.KMS.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to parse key ID from plugin name %q: %w", provider.KMS.Name, err)
			}
			if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
				return nil, fmt.Errorf("key ID %q is not a valid integer: %w", keyID, err)
			}
			kmsCopy := provider.KMS.DeepCopy()
			kmsCopy.Name = keyID
			if existing, exists := byKeyID[keyID]; exists {
				if !equality.Semantic.DeepEqual(existing, kmsCopy) {
					return nil, fmt.Errorf("KMS configuration mismatch for keyID %s: configs from different resources must be identical", keyID)
				}
			}
			byKeyID[keyID] = kmsCopy
		}
	}

	result := make([]*apiserverconfigv1.KMSConfiguration, 0, len(byKeyID))
	for _, v := range byKeyID {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		iKeyID, _ := strconv.ParseUint(result[i].Name, 10, 64)
		jKeyID, _ := strconv.ParseUint(result[j].Name, 10, 64)
		return iKeyID > jKeyID
	})
	return result, nil
}

const pluginConfigDataKeyPrefix = "kms-plugin-config-"

func (d *KMSPlugins) writeTo(target map[string][]byte) error {
	for keyID, pluginConfig := range *d {
		if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
			return fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
		}
		encoded, err := encoding.EncodeKMSPluginConfig(pluginConfig)
		if err != nil {
			return fmt.Errorf("failed to encode KMS plugin config for key %s: %w", keyID, err)
		}
		target[pluginConfigDataKeyPrefix+keyID] = encoded
	}
	return nil
}

func (d *KMSPlugins) readFrom(source map[string][]byte) error {
	for key, value := range source {
		keyID, found := strings.CutPrefix(key, pluginConfigDataKeyPrefix)
		if !found || len(keyID) == 0 {
			continue
		}
		if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
			return fmt.Errorf("failed to extract keyID from data key %s: invalid keyID %q", key, keyID)
		}
		pluginConfig, err := encoding.DecodeKMSPluginConfig(value)
		if err != nil {
			return fmt.Errorf("failed to decode KMS plugin config for key %s: %w", keyID, err)
		}
		if _, exists := (*d)[keyID]; exists {
			return fmt.Errorf("duplicate KMS plugin config for keyID %s", keyID)
		}
		d.Set(keyID, pluginConfig)
	}
	return nil
}

func (d *KMSPluginsSecretData) writeTo(target map[string][]byte) error {
	for keyID, perKeyData := range *d {
		if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
			return fmt.Errorf("invalid keyID %q: must be a non-negative integer", keyID)
		}
		for flatKey, value := range perKeyData.FlatEntries() {
			target[encryptionConfigSecretDataPrefix+flatKey+"-"+keyID] = value
		}
	}
	return nil
}

func (d *KMSPluginsSecretData) readFrom(source map[string][]byte) error {
	for key, value := range source {
		rest, found := strings.CutPrefix(key, encryptionConfigSecretDataPrefix)
		if !found {
			continue
		}
		i := strings.LastIndex(rest, "-")
		if i < 1 {
			continue
		}
		keyID := rest[i+1:]
		if _, err := strconv.ParseUint(keyID, 10, 64); err != nil {
			return fmt.Errorf("failed to extract keyID from key %s: invalid keyID %q", key, keyID)
		}
		sd := (*d)[keyID]
		if err := sd.SetFromCombinedKey(rest[:i], value); err != nil {
			return fmt.Errorf("failed to parse key %s: %w", key, err)
		}
		d.Set(keyID, sd)
	}
	return nil
}
