package kms

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const (
	WellKnownVaultNamespace   = "vault-kms"
	WellKnownVaultImage       = "docker.io/hashicorp/vault-enterprise:2.0.0-ent"
	WellKnownVaultServiceName = "vault"
	DefaultVaultReplicas      = 1

	VaultTransitMount   = "transit"
	VaultTransitKeyName = "kubernetes-encryption-key"

	vaultCredentialsSecretName = "vault-credentials"
	vaultPollTimeout           = 5 * time.Minute

	kmsPolicy = `
path "transit/encrypt/kubernetes-encryption-key" {
  capabilities = ["update"]
}
path "transit/decrypt/kubernetes-encryption-key" {
  capabilities = ["update"]
}
`
)

var vaultSharedManifestFiles = []string{
	"vault_namespace.yaml",
	"vault_serviceaccount.yaml",
	"vault_scc_rolebinding.yaml",
	"vault_configmap.yaml",
	"vault_service.yaml",
}

var vaultDeploymentManifestFile = "vault_deployment.yaml"

// VaultConfig holds the configuration for Vault deployment.
type VaultConfig struct {
	Namespace string
	Image     string
	Replicas  int
}

// VaultCredentials holds the AppRole credentials and root token returned after
// Vault has been initialized and configured.
type VaultCredentials struct {
	RoleID   string
	SecretID string
}

// VaultDeployer manages the deployment and lifecycle of HashiCorp Vault Enterprise
// for KMS encryption testing. After applying manifests, it uses the Vault Go
// client (via oc port-forward) to initialize, unseal, and configure Vault.
type VaultDeployer struct {
	config     *VaultConfig
	kubeClient kubernetes.Interface
	t          testing.TB
}

// NewVaultDeployer creates a new VaultDeployer with the given configuration.
func NewVaultDeployer(t testing.TB, kubeClient kubernetes.Interface, config *VaultConfig) *VaultDeployer {
	t.Helper()

	if config == nil {
		config = &VaultConfig{}
	}
	if config.Namespace == "" {
		config.Namespace = WellKnownVaultNamespace
	}
	if config.Image == "" {
		config.Image = WellKnownVaultImage
	}
	if config.Replicas == 0 {
		config.Replicas = DefaultVaultReplicas
	}

	return &VaultDeployer{
		config:     config,
		kubeClient: kubeClient,
		t:          t,
	}
}

// Deploy deploys HashiCorp Vault Enterprise and waits for it to be fully
// initialized, unsealed, and configured for KMS testing.
//
// The VAULT_LICENSE environment variable must be set with the Vault Enterprise
// license. The deployer creates a K8s Secret from it, which is mounted into
// the Vault pod.
//
// After the pod is ready, the deployer port-forwards to the Vault service and
// uses the Vault Go client to initialize, unseal, enable the transit engine,
// create the encryption key, set up AppRole auth, and store credentials in a
// Kubernetes Secret.
func (d *VaultDeployer) Deploy(ctx context.Context) (*VaultCredentials, error) {
	d.t.Helper()
	d.t.Logf("Deploying Vault Enterprise in namespace %q (replicas: %d)", d.config.Namespace, d.config.Replicas)

	if err := d.applyManifests(ctx); err != nil {
		return nil, fmt.Errorf("failed to apply manifests: %w", err)
	}

	if err := d.waitForDeploymentReady(ctx); err != nil {
		return nil, fmt.Errorf("vault deployment not ready: %w", err)
	}

	creds, err := d.configureVault(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to configure vault: %w", err)
	}

	return creds, nil
}

// applyManifests creates the license secret from VAULT_LICENSE env var and
// applies all static Vault Kubernetes manifests.
func (d *VaultDeployer) applyManifests(ctx context.Context) error {
	d.t.Helper()

	recorder := events.NewInMemoryRecorder("vault-deployer", clock.RealClock{})
	assetFunc := d.assetFunc()

	clientHolder := resourceapply.NewKubeClientHolder(d.kubeClient)
	results := resourceapply.ApplyDirectly(ctx, clientHolder, recorder, resourceapply.NewResourceCache(), assetFunc, vaultSharedManifestFiles...)
	for _, result := range results {
		if result.Error != nil {
			return result.Error
		}
		d.t.Logf("Applied %s (changed=%v)", result.File, result.Changed)
	}

	if err := d.createLicenseSecret(ctx); err != nil {
		return fmt.Errorf("failed to create license secret: %w", err)
	}

	rawDeployment, err := assetFunc(vaultDeploymentManifestFile)
	if err != nil {
		return fmt.Errorf("failed to read deployment manifest: %w", err)
	}
	deployment := resourceread.ReadDeploymentV1OrDie(rawDeployment)
	_, changed, err := resourceapply.ApplyDeployment(ctx, d.kubeClient.AppsV1(), recorder, deployment, -1)
	if err != nil {
		return fmt.Errorf("failed to apply deployment: %w", err)
	}
	d.t.Logf("Applied %s (changed=%v)", vaultDeploymentManifestFile, changed)

	return nil
}

// createLicenseSecret creates a Kubernetes Secret from the VAULT_LICENSE env var.
func (d *VaultDeployer) createLicenseSecret(ctx context.Context) error {
	d.t.Helper()

	license := os.Getenv("VAULT_LICENSE")
	if license == "" {
		d.t.Logf("VAULT_LICENSE env var not set, skipping license secret creation")
		return nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-license",
			Namespace: d.config.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"license": []byte(license),
		},
	}

	_, err := d.kubeClient.CoreV1().Secrets(d.config.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			d.t.Logf("License secret already exists, updating")
			_, err = d.kubeClient.CoreV1().Secrets(d.config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
			return err
		}
		return err
	}
	d.t.Logf("Created vault-license secret from VAULT_LICENSE env var")
	return nil
}

// waitForDeploymentReady waits for the Vault Deployment to have all replicas ready.
func (d *VaultDeployer) waitForDeploymentReady(ctx context.Context) error {
	d.t.Helper()
	d.t.Logf("Waiting for Vault deployment to be ready...")

	return wait.PollUntilContextTimeout(ctx, 2*time.Second, vaultPollTimeout, true, func(ctx context.Context) (bool, error) {
		dep, err := d.kubeClient.AppsV1().Deployments(d.config.Namespace).Get(ctx, "vault", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		desired := int32(d.config.Replicas)
		d.t.Logf("Vault deployment: desired=%d ready=%d available=%d",
			desired, dep.Status.ReadyReplicas, dep.Status.AvailableReplicas)
		return dep.Status.ReadyReplicas >= desired, nil
	})
}

// configureVault port-forwards to the Vault service, initializes, unseals,
// and configures Vault for KMS testing using the Vault Go client.
func (d *VaultDeployer) configureVault(ctx context.Context) (*VaultCredentials, error) {
	d.t.Helper()

	client, done, err := d.newVaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}
	defer done()

	d.t.Logf("Initializing Vault...")
	initResp, err := client.Sys().InitWithContext(ctx, &vaultapi.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init vault: %w", err)
	}

	d.t.Logf("Unsealing Vault...")
	_, err = client.Sys().UnsealWithContext(ctx, initResp.KeysB64[0])
	if err != nil {
		return nil, fmt.Errorf("failed to unseal vault: %w", err)
	}

	client.SetToken(initResp.RootToken)

	d.t.Logf("Enabling transit secret engine...")
	err = client.Sys().MountWithContext(ctx, VaultTransitMount, &vaultapi.MountInput{
		Type: "transit",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enable transit engine: %w", err)
	}

	d.t.Logf("Creating transit encryption key %q...", VaultTransitKeyName)
	_, err = client.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/keys/%s", VaultTransitMount, VaultTransitKeyName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create transit key: %w", err)
	}

	d.t.Logf("Enabling AppRole auth...")
	err = client.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &vaultapi.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enable approle auth: %w", err)
	}

	d.t.Logf("Creating KMS policy...")
	err = client.Sys().PutPolicyWithContext(ctx, "kms-policy", kmsPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms policy: %w", err)
	}

	d.t.Logf("Creating AppRole role...")
	_, err = client.Logical().WriteWithContext(ctx, "auth/approle/role/kms-plugin", map[string]interface{}{
		"token_policies": "kms-policy",
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create approle role: %w", err)
	}

	roleIDSecret, err := client.Logical().ReadWithContext(ctx, "auth/approle/role/kms-plugin/role-id")
	if err != nil {
		return nil, fmt.Errorf("failed to read role-id: %w", err)
	}
	roleID, ok := roleIDSecret.Data["role_id"].(string)
	if !ok {
		return nil, fmt.Errorf("role_id not found or not a string")
	}

	secretIDSecret, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/kms-plugin/secret-id", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret-id: %w", err)
	}
	secretID, ok := secretIDSecret.Data["secret_id"].(string)
	if !ok {
		return nil, fmt.Errorf("secret_id not found or not a string")
	}

	creds := &VaultCredentials{
		RoleID:   roleID,
		SecretID: secretID,
	}

	if err := d.storeCredentials(ctx, creds); err != nil {
		return nil, fmt.Errorf("failed to store vault credentials: %w", err)
	}

	d.t.Logf("Vault configured successfully")
	return creds, nil
}

// storeCredentials creates a Kubernetes Secret with the Vault AppRole credentials.
func (d *VaultDeployer) storeCredentials(ctx context.Context, creds *VaultCredentials) error {
	d.t.Helper()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vaultCredentialsSecretName,
			Namespace: d.config.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"role-id":   []byte(creds.RoleID),
			"secret-id": []byte(creds.SecretID),
		},
	}

	_, err := d.kubeClient.CoreV1().Secrets(d.config.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			_, err = d.kubeClient.CoreV1().Secrets(d.config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
			return err
		}
		return err
	}

	d.t.Logf("Created %s secret with AppRole credentials", vaultCredentialsSecretName)
	return nil
}

// newVaultClient establishes a port-forward to the Vault service and returns
// a configured Vault API client. The caller must call the returned cleanup
// function to terminate the port-forward.
func (d *VaultDeployer) newVaultClient() (*vaultapi.Client, func(), error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "oc", "port-forward",
		fmt.Sprintf("service/%s", WellKnownVaultServiceName), ":8200",
		"-n", d.config.Namespace,
	)

	done := func() {
		cancel()
		_ = cmd.Wait()
	}

	var err error
	defer func() {
		if err != nil {
			done()
		}
	}()

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	if err = cmd.Start(); err != nil {
		return nil, nil, err
	}

	scanner := bufio.NewScanner(stdOut)
	if !scanner.Scan() {
		err = fmt.Errorf("failed to scan port-forward stdout")
		return nil, nil, err
	}
	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}
	output := scanner.Text()

	port := strings.TrimSuffix(strings.TrimPrefix(output, "Forwarding from 127.0.0.1:"), " -> 8200")
	if _, err = strconv.Atoi(port); err != nil {
		err = fmt.Errorf("port-forward output not in expected format: %s", output)
		return nil, nil, err
	}

	d.t.Logf("Port-forwarding to Vault at 127.0.0.1:%s", port)

	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = fmt.Sprintf("http://127.0.0.1:%s", port)

	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create vault api client: %w", err)
	}

	return client, done, nil
}

// assetFunc returns an AssetFunc that templates Vault YAML manifests.
func (d *VaultDeployer) assetFunc() resourceapply.AssetFunc {
	return func(name string) ([]byte, error) {
		content, err := assetsFS.ReadFile(filepath.Join("assets", name))
		if err != nil {
			return nil, err
		}

		tmpl, err := template.New(name).Parse(string(content))
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, d.config); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}
}
