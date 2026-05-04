package codec

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	utilruntime.Must(apiserverconfigv1.AddToScheme(scheme))
	utilruntime.Must(configv1.AddToScheme(scheme))
}

func EncodeEncryptionConfiguration(encryptionConfig *apiserverconfigv1.EncryptionConfiguration) ([]byte, error) {
	encoder := codecs.LegacyCodec(apiserverconfigv1.SchemeGroupVersion)
	data, err := runtime.Encode(encoder, encryptionConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode EncryptionConfiguration: %w", err)
	}
	return data, nil
}

func DecodeEncryptionConfiguration(data []byte) (*apiserverconfigv1.EncryptionConfiguration, error) {
	decoder := codecs.UniversalDecoder(apiserverconfigv1.SchemeGroupVersion)
	obj, err := runtime.Decode(decoder, data)
	if err != nil {
		return nil, err
	}
	encryptionConfig, ok := obj.(*apiserverconfigv1.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T, expected *EncryptionConfiguration", obj)
	}
	return encryptionConfig, nil
}

// EncodeKMSConfiguration encodes a KMSConfiguration by wrapping it in an
// EncryptionConfiguration envelope, since KMSConfiguration is not a runtime.Object.
func EncodeKMSConfiguration(encryption *apiserverconfigv1.KMSConfiguration) ([]byte, error) {
	encryptionConfiguration := &apiserverconfigv1.EncryptionConfiguration{
		Resources: []apiserverconfigv1.ResourceConfiguration{
			{
				Providers: []apiserverconfigv1.ProviderConfiguration{
					{KMS: encryption},
				},
			},
		},
	}
	return EncodeEncryptionConfiguration(encryptionConfiguration)
}

// DecodeKMSConfiguration decodes a KMSConfiguration from an EncryptionConfiguration
// envelope, since KMSConfiguration is not a runtime.Object.
func DecodeKMSConfiguration(data []byte) (*apiserverconfigv1.KMSConfiguration, error) {
	encryptionConfiguration, err := DecodeEncryptionConfiguration(data)
	if err != nil {
		return nil, err
	}
	if len(encryptionConfiguration.Resources) != 1 || len(encryptionConfiguration.Resources[0].Providers) != 1 {
		return nil, fmt.Errorf("invalid KMS encryption config: expected exactly 1 resource with 1 provider")
	}
	if encryptionConfiguration.Resources[0].Providers[0].KMS == nil {
		return nil, fmt.Errorf("invalid KMS encryption config: provider has no KMS configuration")
	}
	return encryptionConfiguration.Resources[0].Providers[0].KMS, nil
}

// EncodeKMSConfig encodes a KMSConfig by wrapping it in an APIServer
// envelope, since KMSConfig is not a runtime.Object.
func EncodeKMSConfig(kmsConfig *configv1.KMSConfig) ([]byte, error) {
	apiServerObj := &configv1.APIServer{
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				KMS: kmsConfig,
			},
		},
	}
	encoder := codecs.LegacyCodec(configv1.SchemeGroupVersion)
	data, err := runtime.Encode(encoder, apiServerObj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode KMS provider config: %w", err)
	}
	return data, nil
}

// DecodeKMSConfig decodes a KMSConfig from an APIServer envelope,
// since KMSConfig is not a runtime.Object.
func DecodeKMSConfig(data []byte) (*configv1.KMSConfig, error) {
	apiServer := &configv1.APIServer{}
	err := runtime.DecodeInto(codecs.UniversalDecoder(configv1.SchemeGroupVersion), data, apiServer)
	if err != nil {
		return nil, err
	}
	if apiServer.Spec.Encryption.KMS == nil {
		return nil, fmt.Errorf("decoded APIServer envelope contains no KMS config")
	}
	return apiServer.Spec.Encryption.KMS, nil
}
