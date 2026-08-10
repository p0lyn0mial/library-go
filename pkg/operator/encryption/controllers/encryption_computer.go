package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

var _ EncryptionConfigurationComputer = &EncryptionComputer{}

// EncryptionComputer accepts a keyController and a stateController and
// allows computing their outputs without side effects.
type EncryptionComputer struct {
	keyController   *keyController
	stateController *stateController
	// syncCtx is used by ComputeEncryptionConfiguration; it holds a single
	// rate-limiting queue whose goroutine lives for the lifetime of this object.
	// Re-queue requests issued during computation are intentionally discarded.
	syncCtx factory.SyncContext
}

func NewEncryptionComputer(keyCtrl *keyController, stateCtrl *stateController) *EncryptionComputer {
	return &EncryptionComputer{
		keyController:   keyCtrl,
		stateController: stateCtrl,
		syncCtx: factory.NewSyncContext(
			"EncryptionConfigurationComputer",
			events.NewLoggingEventRecorder("encryption-configuration-computer", clock.RealClock{}),
		),
	}
}

// ComputeKeySecret returns the key secret that would be created by the
// key controller, or nil if no new key is needed.
func (e *EncryptionComputer) ComputeKeySecret(ctx context.Context, syncCtx factory.SyncContext) (*corev1.Secret, error) {
	return e.keyController.computeKeySecret(ctx, syncCtx)
}

// ComputeEncryptionConfigSecret returns the encryption config secret that
// would be applied by the state controller, or nil if no update is needed.
func (e *EncryptionComputer) ComputeEncryptionConfigSecret(ctx context.Context, queue workqueue.RateLimitingInterface) (*corev1.Secret, []eventWithReason, error) {
	return e.stateController.computeEncryptionConfigSecret(ctx, queue)
}

// ComputeEncryptionConfiguration implements EncryptionConfigurationComputer.
// It computes the encryption configuration that would result after creating
// the next key, giving the KMS preflight deployer the configuration it needs
// to test the plugin before the key is actually created.
func (e *EncryptionComputer) ComputeEncryptionConfiguration(ctx context.Context) (*corev1.Secret, error) {
	secret, _, err := e.ComputeEncryptionConfigSecretWithNewKey(ctx, e.syncCtx)
	return secret, err
}

// ComputeEncryptionConfigSecretWithNewKey computes the key secret that
// would be created by the key controller and propagates it into the state
// controller's computation, returning the encryption config secret that
// would result if the new key had been created.
func (e *EncryptionComputer) ComputeEncryptionConfigSecretWithNewKey(ctx context.Context, syncCtx factory.SyncContext) (*corev1.Secret, []eventWithReason, error) {
	newKeySecret, err := e.keyController.computeKeySecret(ctx, syncCtx)
	if err != nil {
		return nil, nil, err
	}

	sc := e.stateController
	listKeySecretsFn := sc.listKeySecretsFn
	if newKeySecret != nil {
		listKeySecretsFn = func(ctx context.Context) ([]*corev1.Secret, error) {
			existing, err := sc.listKeySecretsFn(ctx)
			if err != nil {
				return nil, err
			}
			return append([]*corev1.Secret{newKeySecret}, existing...), nil
		}
	}

	return sc.computeEncryptionConfigSecretWithCustomListKeySecretFn(ctx, syncCtx.Queue(), listKeySecretsFn)
}

// NewEncryptionComputerWithControllers creates a new EncryptionComputer backed by
// freshly constructed key and state controllers that share the same underlying
// *keyController and *stateController instances. It returns the computer together
// with the two factory.Controller values (key and state) so callers can run them.
func NewEncryptionComputerWithControllers(
	component string,
	unsupportedConfigPrefix []string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretsClient corev1client.SecretsGetter,
	configMapClient corev1client.ConfigMapsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
	encryptionStatusProvider kms.EncryptionStatusProvider,
) (*EncryptionComputer, factory.Controller, factory.Controller) {
	keyCtrl := newKeyControllerInternal(
		component, unsupportedConfigPrefix, provider, deployer, preconditionsFulfilledFn,
		operatorClient, apiServerClient, secretsClient, configMapClient,
		encryptionSecretSelector, encryptionStatusProvider,
	)
	stateCtrl := newStateControllerInternal(
		component, provider, deployer, preconditionsFulfilledFn,
		operatorClient, secretsClient, encryptionSecretSelector,
	)
	computer := NewEncryptionComputer(keyCtrl, stateCtrl)
	keyFactory := newKeyControllerFactory(keyCtrl, apiServerInformer, kubeInformersForNamespaces, eventRecorder)
	stateFactory := newStateControllerFactory(stateCtrl, apiServerInformer, kubeInformersForNamespaces, eventRecorder)
	return computer, keyFactory, stateFactory
}
