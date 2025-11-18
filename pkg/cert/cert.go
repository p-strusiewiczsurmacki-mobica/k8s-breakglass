package cert

import (
	"fmt"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations;validatingwebhookconfigurations,verbs=get;list;watch;update

const (
	DefaultWebhookPath = "/tmp/k8s-webhook-server/serving-certs"
	DefaultTLSCertFile = "tls.crt"
	DefaultTLSKeyFile  = "tls.key"

	DefaultValidatingWebhookConfigurationName = "breakglass-validating-webhook-configuration"
)

func SetupRotator(mgr ctrl.Manager, name, namespace, path, validatingWebhookConfigurationName string, setupFinished chan struct{}) error {
	if path == "" {
		path = DefaultWebhookPath
	}

	if validatingWebhookConfigurationName == "" {
		validatingWebhookConfigurationName = DefaultValidatingWebhookConfigurationName
	}

	cr := &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		},
		CertDir:               path,
		CAName:                fmt.Sprintf("%s-ca", name),
		CAOrganization:        "breakglass",
		DNSName:               fmt.Sprintf("%s.%s.svc", name, namespace),
		ExtraDNSNames:         []string{fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)},
		IsReady:               setupFinished,
		RequireLeaderElection: false,
		Webhooks: []rotator.WebhookInfo{
			{
				Name: validatingWebhookConfigurationName,
				Type: rotator.Validating,
			},
		},
		RestartOnSecretRefresh: false,
	}

	if err := rotator.AddRotator(mgr, cr); err != nil {
		return fmt.Errorf("unable to setup cert rotation: %w", err)
	}

	return nil
}
