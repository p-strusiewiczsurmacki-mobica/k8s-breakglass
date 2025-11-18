package cert

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations;validatingwebhookconfigurations,verbs=get;list;watch;update

func SetupRotator(mgr ctrl.Manager, objectType, name, namespace string, setupFinished chan struct{}) (chan struct{}, error) {
	webhooks := []rotator.WebhookInfo{
		{
			Name: "breakglass-webhook-service",
			Type: rotator.Validating,
		},
	}

	if err := rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		},
		CertDir:                "/certs",
		CAName:                 "breakglass-webhook-ca",
		CAOrganization:         "coil",
		DNSName:                fmt.Sprintf("%s.%s.svc", name, namespace),
		ExtraDNSNames:          []string{fmt.Sprintf("%s.%s.svc.cluster.local", name, namespace)},
		IsReady:                setupFinished,
		RequireLeaderElection:  true,
		Webhooks:               webhooks,
		RestartOnSecretRefresh: false,
	}); err != nil {
		return nil, fmt.Errorf("unable to set up cert rotation: %w", err)
	}

	return setupFinished, nil
}

func WaitForExit(setupErr, mgrErr chan error, cancel context.CancelFunc) error {
	logger := ctrl.Log.WithName("coil")
	for {
		select {
		case err := <-setupErr:
			if err != nil {
				logger.Error(err, "unable to setup reconcilers")
				cancel() // if error occurred during setup cancel manager's context
			}
		case err := <-mgrErr:
			if err != nil {
				return fmt.Errorf("manager error: %w", err)
			}
			return nil
		}
	}
}
