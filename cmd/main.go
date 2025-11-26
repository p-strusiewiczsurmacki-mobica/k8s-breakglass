package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cert"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/leaderelection"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/reconciler"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
)

func main() {
	// DEPLOYMENT PATTERNS
	// ===================
	// The breakglass controller supports multiple deployment patterns via component enable flags:
	//
	// 1. MONOLITHIC (default):
	//    All components run in a single instance. Use defaults or:
	//    breakglass-controller
	//
	// 2. WEBHOOK-ONLY INSTANCE (validating webhooks only):
	//    Runs only Kubernetes validating webhooks (CRD validation) with separate metrics.
	//    breakglass-controller \
	//      --enable-frontend=false \
	//      --enable-api=false \
	//      --enable-cleanup=false \
	//      --webhooks-metrics-bind-address=0.0.0.0:8083
	//
	// 3. API-ONLY INSTANCE (frontend, REST API, SAR webhook):
	//    Runs API endpoints (Session/Escalation), web UI, and SAR authorization webhook.
	//    breakglass-controller \
	//      --enable-webhooks=false \
	//      --enable-cleanup=false
	//
	// 4. FRONTEND-ONLY INSTANCE:
	//    Runs only the frontend web UI without webhooks, API, or SAR.
	//    breakglass-controller \
	//      --enable-api=false \
	//      --enable-webhooks=false \
	//      --enable-cleanup=false
	//
	// 5. CLEANUP-ONLY INSTANCE:
	//    Runs only the background cleanup routine for expired sessions.
	//    breakglass-controller \
	//      --enable-frontend=false \
	//      --enable-api=false \
	//      --enable-webhooks=false
	//
	// COMPONENT ARCHITECTURE
	// ======================
	// Frontend/API/SAR:      Gin HTTP server (port 8080) - runs if enable-frontend or enable-api
	// Validating Webhooks:   controller-runtime webhook server (port 9443) - runs if enable-webhooks
	// Cleanup Routine:       background goroutine - runs if enable-cleanup
	//
	// METRICS SEPARATION
	// ==================
	// The --webhooks-metrics-bind-address flag allows running a separate metrics server for webhooks.
	// This is useful for multi-instance deployments where you want to scrape metrics separately:
	//
	//   API/Reconciler metrics:  0.0.0.0:8080  (main controller metrics)
	//   Webhook metrics:         0.0.0.0:8081  (webhook-specific metrics)
	//   Health probe:            0.0.0.0:8082  (health checks)
	//
	// ENVIRONMENT VARIABLES
	// =====================
	// All flags can be set via environment variables with UPPERCASE_SNAKE_CASE names:
	//   ENABLE_FRONTEND=true          # Web UI
	//   ENABLE_API=true               # REST API and SAR webhook
	//   ENABLE_CLEANUP=true           # Background cleanup
	//   ENABLE_WEBHOOKS=true          # Validating webhooks (CRD validation)
	//   ENABLE_VALIDATING_WEBHOOKS=true  # Which validating webhooks to register
	//   WEBHOOKS_METRICS_BIND_ADDRESS=0.0.0.0:8083  # Separate metrics for webhooks
	//

	cliConfig := cli.Parse()

	// Setup logging with zap
	var zapLogger *zap.Logger
	var err error

	if zapLogger, err = utils.SetupLogger(cliConfig.Debug); err != nil {
		panic(fmt.Errorf("Failed to setup logger: %w", err))
	}

	defer func() {
		_ = zapLogger.Sync()
	}()

	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	log := zapLogger.Sugar()
	log.Infof("Starting breakglass controller (version: %s)", system.Version)

	if cliConfig.Debug {
		log.Debug("Debug logging enabled")
	}

	// Log all startup configuration flags for debuggability
	cliConfig.Print(log)

	// Load configuration from config.yaml
	cfg, err := config.Load(cliConfig.ConfigPath)
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
	}

	if cliConfig.Debug {
		log.Infof("Configuration: %#v", cfg)
	}

	// Setup authentication
	auth := api.NewAuth(log, cfg)
	server := api.NewServer(zapLogger, cfg, cliConfig.Debug, auth)

	kubeContext := cfg.Kubernetes.Context
	sessionManager, err := breakglass.NewSessionManager(kubeContext)
	if err != nil {
		log.Fatalf("Error creating breakglass session manager: %v", err)
	}

	// Create a unified scheme with all CRDs registered
	scheme, err := utils.CreateScheme()
	if err != nil {
		log.Fatalf("failed to create scheme: %w", err)
	}
	log.Debugw("Scheme initialized with CRDs", "types", "corev1, BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider, DenyPolicy")

	reconcilerMgr, err := createReconcilerManager(restConfig, scheme, log,
		metricsAddr, metricsSecure, metricsCertPath, metricsCertName, metricsCertKey,
		probeAddr, enableHTTP2)
	if err != nil {
		log.Fatalf("Failed to create controller-runtime manager: %v", err)
	}
	indexer.RegisterCommonFieldIndexes(context.Background(), reconcilerMgr.GetFieldIndexer(), log)

	kubeClient := reconcilerMgr.GetClient()
	sessionManager := breakglass.NewSessionManagerWithClient(reconcilerMgr.GetClient())

	// Load IdentityProvider configuration for group sync
	idpLoader := config.NewIdentityProviderLoader(kubeClient)
	idpLoader.WithLogger(log)

	// Set up metrics recorder for conversion failures
	idpLoader.WithMetricsRecorder(func(idpName, failureReason string) {
		metrics.IdentityProviderConversionErrors.WithLabelValues(idpName, failureReason).Inc()
	})

	// Validate IdentityProvider exists (mandatory)
	ctx := context.Background()

	idpLoader, err := config.DefaultIdentityProviderLoader(ctx, scheme, log)
	if err != nil {
		log.Fatal(err)
	}

	// Load primary IdentityProvider to check for Keycloak group sync
	idpConfig, err := idpLoader.LoadIdentityProvider(ctx)
	if err != nil {
		log.Warnf("Failed to load IdentityProvider: %v; group sync disabled", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("load_error").Inc()
		idpConfig = nil
	}

	resolver := breakglass.SetupResolver(idpConfig, log)

	escalationManager, err := breakglass.NewEscalationManager(kubeContext, resolver)
	if err != nil {
		log.Fatalf("Error creating breakglass escalation manager: %v", err)
	}

	escalationManager := breakglass.NewEscalationManagerWithClient(reconcilerMgr.GetClient(), resolver)

	// Build shared cluster config provider & deny policy evaluator reusing escalation manager client
	ccProvider := cluster.NewClientProvider(escalationManager.Client, log)
	denyEval := policy.NewEvaluator(escalationManager.Client, log)

	mailQueue, err := mail.Setup(ctx, escalationManager.Client, cfg.Frontend.BrandingName, log)
	if err != nil {
		log.Warn(err)
	}

	// Enable multi-IDP support in auth handler for token verification
	// This allows the backend to verify tokens from any configured IDP, not just the default one
	auth.WithIdentityProviderLoader(idpLoader)

	// Setup session controller with all dependencies
	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, &escalationManager,
		auth.Middleware(), cliConfig.ConfigPath, ccProvider, escalationManager.Client, cliConfig.DisableEmail).WithQueue(mailQueue)

	// Register API controllers based on component flags
	apiControllers := api.Setup(sessionController, &escalationManager, &sessionManager, cliConfig.EnableFrontend,
		cliConfig.EnableAPI, cliConfig.ConfigPath, auth, ccProvider, denyEval, &cfg, log)

	// Make IdentityProvider available to API server for frontend configuration
	if idpConfig != nil {
		server.SetIdentityProvider(idpConfig)
		log.Infow("identity_provider_set_on_api_server", "type", idpConfig.Type)
	}

	// Both frontend and API share the same HTTP server, so we check both flags
	shouldEnableHTTPServer := cliConfig.EnableFrontend || cliConfig.EnableAPI

	if shouldEnableHTTPServer {
		err = server.RegisterAll(apiControllers)
		if err != nil {
			log.Fatalf("Error registering breakglass controllers: %v", err)
		}
	} else {
		log.Infow("HTTP server disabled: both --enable-frontend and --enable-api are false")
	}

	// Create a channel to broadcast leadership signal to background loops
	// This enables safe horizontal scaling: only the leader runs cleanup loops
	leaderElectedCh := make(chan struct{})

	var wg sync.WaitGroup

	// Escalation approver group expansion updater (Keycloak read-only sync)
	managerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background routines (cleanup routine is optional)
	if cliConfig.EnableCleanup {
		wg.Add(1)
		go func() {
			defer wg.Done()
			breakglass.CleanupRoutine{Log: log, Manager: &sessionManager, LeaderElected: leaderElectedCh}.CleanupRoutine(managerCtx)
		}()
		log.Infow("Cleanup routine enabled")
	} else {
		log.Infow("Cleanup routine disabled via --enable-cleanup=false")
	}

	if err := cluster.RegisterInvalidationHandlers(managerCtx, reconcilerMgr, ccProvider, log); err != nil {
		log.Warnw("Failed to register cluster cache invalidation handlers", "error", err)
	}

	// Event recorder for emitting Kubernetes events (persisted to API server)
	restCfg := ctrl.GetConfigOrDie()
	kubeClientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("failed to create kubernetes clientset for event recorder: %v", err)
	}

	// Now create the leader election resourcelock using the kubeClientset
	eventBroadcaster := record.NewBroadcaster()
	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: "breakglass-controller"})

	// Start the escalation status updater with EventRecorder and IDPLoader so it can:
	// - Emit events when IDP group sync fails (surfaced via kubectl describe identityprovider)
	// - Fetch group members from multiple IDPs for status.groupSyncErrors and status.IDPGroupMemberships
	wg.Add(1)
	go func() {
		defer wg.Done()
		breakglass.EscalationStatusUpdater{
			Log:           log,
			K8sClient:     escalationManager.Client,
			Resolver:      escalationManager.Resolver,
			EventRecorder: eventRecorder,
			IDPLoader:     idpLoader,
			Interval:      cli.ParseEscalationStatusUpdateInterval(cliConfig.EscalationStatusUpdateInt, log),
			LeaderElected: leaderElectedCh,
		}.Start(managerCtx)
	}()

	// Determine the namespace for the lease
	// If not specified via flag, use the pod's namespace from the environment
	leaseName := cliConfig.LeaderElectID
	leaseNamespace := cliConfig.LeaderElectNamespace
	if leaseNamespace == "" {
		leaseNamespace = cliConfig.PodNamespace
	}
	if leaseNamespace == "" {
		leaseNamespace = "default"
	}

	log.Infow("Creating leader election lease", "id", leaseName, "namespace", leaseNamespace)

	// Get hostname for the resourcelock identity
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname for leader election: %v", err)
	}

	// Create the resourcelock directly using resourcelock.New
	// This will automatically create the lease if it doesn't exist
	resourceLock, err := resourcelock.New(
		"leases",
		leaseNamespace,
		leaseName,
		kubeClientset.CoreV1(),
		kubeClientset.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      hostname,
			EventRecorder: eventRecorder,
		},
	)
	if err != nil {
		log.Fatalf("Failed to create leader election resource lock: %v", err)
	}
	log.Infow("Leader election resource lock created", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)

	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: cliConfig.PodNamespace, Logger: log}

	// Determine interval from CLI flag first, then config (fallback to 10m)
	intervalStr := cliConfig.ClusterConfigCheckInterval
	if intervalStr == "" && cfg.Kubernetes.ClusterConfigCheckInterval != "" {
		intervalStr = cfg.Kubernetes.ClusterConfigCheckInterval
	}
	interval := cli.ParseClusterConfigCheckInterval(intervalStr, log)

	// ClusterConfig checker: validates that referenced kubeconfig secrets contain the expected key
	wg.Add(1)
	go func() {
		defer wg.Done()
		breakglass.ClusterConfigChecker{Log: log, Client: escalationManager.Client, Recorder: recorder, Interval: interval, LeaderElected: leaderElectedCh}.Start(managerCtx)
	}()

	var certsReady chan struct{}
	certMgrErr := make(chan error)
	defer close(certMgrErr)

	if cliConfig.EnableWebhooks && cliConfig.Webhook.CertGeneration {
		certsReady = make(chan struct{})
		certMgr := cert.NewManager(cliConfig.Webhook.SvcName, cliConfig.BreakglassNamespace, cliConfig.Webhook.CertPath,
			cliConfig.Webhook.ValidatingConfigName, certsReady, leaderElectedCh, log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := certMgr.Start(managerCtx, scheme); err != nil {
				// log.Errorw("certificate manager failed", "err", err)
				certMgrErr <- err
			}
		}()
	}

	// Start leader election if enabled
	// This coordinates background loops (cleanup, escalation updater, cluster config checker)
	// to run only on the leader replica using the resourcelock
	if cliConfig.EnableLeaderElection {
		wg.Add(1)
		go func() {
			leaderelection.Run(managerCtx, &wg, leaderElectedCh, resourceLock, hostname, leaseName, leaseNamespace, log)
		}()
	} else {
		// If leader election is disabled, immediately signal that we're the leader
		// This allows background loops to run on all replicas
		log.Infow("Leader election disabled via --enable-leader-election=false, background loops will run on all replicas")
		close(leaderElectedCh)
	}

	// Always start the reconciler manager (field indices and reconcilers always run)
	// The manager does NOT do leader election; background loops handle that
	recMgrErr := make(chan error)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := setupReconcilerManager(managerCtx, log, reconcilerMgr, idpLoader, server); err != nil {
			recMgrErr <- err
		}
		if err := reconciler.Setup(managerCtx, log, scheme, idpLoader, server, cliConfig.MetricsAddr,
			cliConfig.MetricsSecure, cliConfig.MetricsCertPath, cliConfig.MetricsCertName,
			cliConfig.MetricsCertKey, cliConfig.ProbeAddr, cliConfig.EnableHTTP2); err != nil {
			recMgrErr <- err
		}
	}()

	// Optionally setup webhooks if enabled (webhooks are optional, reconcilers are not)
	webhookErr := make(chan error)
	defer close(webhookErr)

	if cliConfig.EnableWebhooks {
		log.Infow("Webhooks enabled via --enable-webhooks flag")
		if cliConfig.Webhook.CertGeneration {
			if err := cert.Ensure(cliConfig.Webhook.CertPath, cliConfig.Webhook.CertName, certsReady, certMgrErr, log); err != nil {
				log.Fatal(err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := webhook.Setup(managerCtx, log, scheme, &cliConfig.Webhook, cliConfig.EnableValidatingWebhooks,
				cliConfig.EnableHTTP2, cliConfig.Webhook.CertGeneration); err != nil {
				webhookErr <- err
			}
		}()
	} else {
		log.Infow("Webhooks disabled via --enable-webhooks flag")
	}

	// Add signal handlers for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start HTTP server (API/Frontend/SAR) if either frontend or API is enabled
	if shouldEnableHTTPServer {
		go func() {
			server.Listen()
		}()
	}

	// Wait for signal and perform graceful shutdown
	select {
	case <-sigChan:
		log.Info("Received shutdown signal, initiating graceful shutdown")
	case err := <-webhookErr:
		log.Errorf("webhook server failed, shutting down: %s", err.Error())
	case err := <-recMgrErr:
		log.Errorf("reconciler manager failed, shutting down: %s", err.Error())
	}

	// Shutdown mail queue with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if mailQueue != nil {
		if err := mailQueue.Stop(shutdownCtx); err != nil {
			log.Warnw("Mail queue shutdown error", "error", err)
		} else {
			log.Info("Mail queue shut down successfully")
		}
	}

	cancel()
	log.Info("Waiting for all goroutines to finish")
	wg.Wait()
	log.Info("Breakglass controller shutdown complete")
}

func setupReconcilerManager(
	ctx context.Context,
	log *zap.SugaredLogger,
	mgr ctrl.Manager,
	idpLoader *config.IdentityProviderLoader,
	server *api.Server,
) error {
	log.Debugw("Starting reconciler manager with unified scheme")

	if mgr == nil {
		return fmt.Errorf("controller-runtime manager is nil; reconcilers will not run")
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add healthz check to reconciler manager: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add readyz check to reconciler manager: %w", err)
	}
	log.Infow("Health check handlers registered")

	// Register IdentityProvider Reconciler with controller-runtime manager
	log.Debugw("Setting up IdentityProvider reconciler")
	idpReconciler := config.NewIdentityProviderReconciler(
		mgr.GetClient(),
		log,
		func(reloadCtx context.Context) error {
			return server.ReloadIdentityProvider(idpLoader)
		},
	)
	idpReconciler.WithErrorHandler(func(ctx context.Context, err error) {
		log.Errorw("IdentityProvider reconciliation error", "error", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("reconciler_error").Inc()
	})
	idpReconciler.WithEventRecorder(mgr.GetEventRecorderFor("breakglass-controller"))
	idpReconciler.WithResyncPeriod(10 * time.Minute)

	// Set reconciler in API server so it can use the cached IDPs
	// This prevents the API from querying the Kubernetes APIServer on every /api/config/idps request
	server.SetIdentityProviderReconciler(idpReconciler)

	if err := idpReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup IdentityProvider reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered IdentityProvider reconciler", "resyncPeriod", "10m")

	// Register BreakglassEscalation Reconciler with controller-runtime manager
	log.Debugw("Setting up BreakglassEscalation reconciler")
	escalationReconciler := config.NewEscalationReconciler(
		mgr.GetClient(),
		log,
		mgr.GetEventRecorderFor("breakglass-escalation-controller"),
		nil, // no onReload callback needed for escalations
		func(ctx context.Context, err error) {
			log.Errorw("BreakglassEscalation reconciliation error", "error", err)
			metrics.IdentityProviderLoadFailed.WithLabelValues("escalation_reconciler_error").Inc()
		},
		10*time.Minute,
	)

	// Set reconciler in API server so it can use the cached escalation→IDP mapping
	// This prevents the API from querying the Kubernetes APIServer on every /api/config/idps request
	server.SetEscalationReconciler(escalationReconciler)

	if err := escalationReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup BreakglassEscalation reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered BreakglassEscalation reconciler", "resyncPeriod", "10m")

	// Note: Leadership election is NOT handled by the manager at this level.
	// Background loops (cleanup, escalation updater, cluster config checker) use the resourcelock
	// to coordinate and run only on the leader. The signal propagation to those loops happens
	// outside this manager in the main() function after the manager and loops are set up.

	// Start manager (blocks) but we run it in a goroutine so it doesn't prevent the API server
	// The manager runs reconcilers on all replicas (no leader election)
	log.Infow("Starting controller-runtime reconciler manager (no leader election at manager level)")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("controller-runtime reconciler manager exited: %w", err)
	}

	return nil
}

func createReconcilerManager(
	restCfg *rest.Config,
	scheme *runtime.Scheme,
	log *zap.SugaredLogger,
	metricsAddr string,
	metricsSecure bool,
	metricsCertPath string,
	metricsCertName string,
	metricsCertKey string,
	probeAddr string,
	enableHTTP2 bool,
) (ctrl.Manager, error) {
	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: metricsSecure,
		TLSOpts:       tlsOpts,
	}

	if len(metricsCertPath) > 0 {
		log.Infow("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName,
			"metrics-cert-key", metricsCertKey)
		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	return ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		WebhookServer:          nil,
		LeaderElection:         false,
	})
}
