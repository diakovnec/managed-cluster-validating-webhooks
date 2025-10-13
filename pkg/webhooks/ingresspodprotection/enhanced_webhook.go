package ingresspodprotection

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/utils"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	EnhancedWebhookName     string = "ingress-pod-protection-enhanced"
	enhancedTargetNamespace string = "openshift-ingress"
	enhancedDocString       string = `Enhanced protection against bulk pod deletion in openshift-ingress namespace using rate limiting and pattern detection.`
)

var (
	enhancedTimeout int32 = 2
	enhancedLog           = logf.Log.WithName(EnhancedWebhookName)
	enhancedScope         = admissionregv1.NamespacedScope
	enhancedRules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &enhancedScope,
			},
		},
	}

	// Users allowed to delete pods in openshift-ingress namespace
	enhancedAllowedUsers = []string{
		"backplane-cluster-admin",
		"system:admin",
	}

	// Groups allowed to delete pods in openshift-ingress namespace
	enhancedAllowedGroups = []string{
		"system:serviceaccounts:openshift-backplane-srep",
		"system:serviceaccounts:openshift-ingress-operator",
	}
)

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	Window          time.Duration // Time window for rate limiting
	MaxDeletions    int           // Maximum deletions allowed in window
	Cooldown        time.Duration // Cooldown period after limit exceeded
	CleanupInterval time.Duration // How often to clean up old data
	MaxUserHistory  int           // Maximum number of users to track
}

// DefaultRateLimitConfig returns sensible defaults
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Window:          2 * time.Minute,  // 2 minute window
		MaxDeletions:    1,                // Max 1 deletion per window (openshift-ingress typically has 2 pods)
		Cooldown:        5 * time.Minute,  // 5 minute cooldown
		CleanupInterval: 10 * time.Minute, // Cleanup every 10 minutes
		MaxUserHistory:  1000,             // Track up to 1000 users
	}
}

// UserActivity tracks deletion activity for a user
type UserActivity struct {
	Deletions    []time.Time
	LastActivity time.Time
	BlockedUntil *time.Time
	TotalBlocks  int // Track how many times user was blocked
}

// EnhancedRateLimiter provides sophisticated rate limiting with memory management
type EnhancedRateLimiter struct {
	mu            sync.RWMutex
	userActivity  map[string]*UserActivity
	config        *RateLimitConfig
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	stats         *RateLimitStats
}

// RateLimitStats tracks webhook statistics
type RateLimitStats struct {
	mu              sync.RWMutex
	TotalRequests   int64
	AllowedRequests int64
	BlockedRequests int64
	CleanupRuns     int64
	LastCleanup     time.Time
}

// NewEnhancedRateLimiter creates a new rate limiter with cleanup
func NewEnhancedRateLimiter(config *RateLimitConfig) *EnhancedRateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	limiter := &EnhancedRateLimiter{
		userActivity: make(map[string]*UserActivity),
		config:       config,
		stopChan:     make(chan struct{}),
		stats:        &RateLimitStats{},
	}

	// Start cleanup routine
	limiter.startCleanupRoutine()

	return limiter
}

// IsBulkDeletionAttempt checks if the request represents a bulk deletion pattern
func (rl *EnhancedRateLimiter) IsBulkDeletionAttempt(request admissionctl.Request) bool {
	rl.stats.mu.Lock()
	rl.stats.TotalRequests++
	rl.stats.mu.Unlock()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	username := request.AdmissionRequest.UserInfo.Username
	now := time.Now()

	// Initialize user activity if not exists
	if rl.userActivity[username] == nil {
		rl.userActivity[username] = &UserActivity{
			Deletions:    make([]time.Time, 0),
			LastActivity: now,
		}
	}

	user := rl.userActivity[username]

	// Check if user is in cooldown period
	if user.BlockedUntil != nil && now.Before(*user.BlockedUntil) {
		rl.stats.mu.Lock()
		rl.stats.BlockedRequests++
		rl.stats.mu.Unlock()
		return true
	}

	// Clean old deletions outside the window
	cutoff := now.Add(-rl.config.Window)
	var validDeletions []time.Time
	for _, deletionTime := range user.Deletions {
		if deletionTime.After(cutoff) {
			validDeletions = append(validDeletions, deletionTime)
		}
	}
	user.Deletions = validDeletions

	// Check if this would exceed the limit
	if len(user.Deletions) >= rl.config.MaxDeletions {
		// Block user for cooldown period
		blockUntil := now.Add(rl.config.Cooldown)
		user.BlockedUntil = &blockUntil
		user.TotalBlocks++

		rl.stats.mu.Lock()
		rl.stats.BlockedRequests++
		rl.stats.mu.Unlock()

		log.Info("Rate limit exceeded",
			"user", username,
			"deletions", len(user.Deletions),
			"window", rl.config.Window,
			"blockedUntil", blockUntil,
			"totalBlocks", user.TotalBlocks)

		return true
	}

	// Add current deletion
	user.Deletions = append(user.Deletions, now)
	user.LastActivity = now

	rl.stats.mu.Lock()
	rl.stats.AllowedRequests++
	rl.stats.mu.Unlock()

	return false
}

// GetUserStatus returns current status for a user
func (rl *EnhancedRateLimiter) GetUserStatus(username string) string {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	user := rl.userActivity[username]
	if user == nil {
		return "No activity"
	}

	if user.BlockedUntil != nil && time.Now().Before(*user.BlockedUntil) {
		return fmt.Sprintf("Blocked until %v (total blocks: %d)", user.BlockedUntil, user.TotalBlocks)
	}

	return fmt.Sprintf("Active deletions: %d (total blocks: %d)", len(user.Deletions), user.TotalBlocks)
}

// GetStats returns current statistics
func (rl *EnhancedRateLimiter) GetStats() map[string]interface{} {
	rl.stats.mu.RLock()
	defer rl.stats.mu.RUnlock()

	rl.mu.RLock()
	userCount := len(rl.userActivity)
	rl.mu.RUnlock()

	return map[string]interface{}{
		"totalRequests":   rl.stats.TotalRequests,
		"allowedRequests": rl.stats.AllowedRequests,
		"blockedRequests": rl.stats.BlockedRequests,
		"activeUsers":     userCount,
		"cleanupRuns":     rl.stats.CleanupRuns,
		"lastCleanup":     rl.stats.LastCleanup,
	}
}

// startCleanupRoutine starts the background cleanup routine
func (rl *EnhancedRateLimiter) startCleanupRoutine() {
	rl.cleanupTicker = time.NewTicker(rl.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-rl.cleanupTicker.C:
				rl.performCleanup()
			case <-rl.stopChan:
				rl.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// performCleanup removes old user data to prevent memory leaks
func (rl *EnhancedRateLimiter) performCleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.config.Window * 2) // Keep data for 2x the window
	removedUsers := 0

	// Remove users with no recent activity
	for username, user := range rl.userActivity {
		if user.LastActivity.Before(cutoff) {
			delete(rl.userActivity, username)
			removedUsers++
		}
	}

	// If we still have too many users, remove oldest ones
	if len(rl.userActivity) > rl.config.MaxUserHistory {
		// Sort users by last activity and remove oldest
		type userInfo struct {
			username string
			activity *UserActivity
		}

		var users []userInfo
		for username, user := range rl.userActivity {
			users = append(users, userInfo{username, user})
		}

		// Simple sort by last activity (oldest first)
		for i := 0; i < len(users)-1; i++ {
			for j := i + 1; j < len(users); j++ {
				if users[i].activity.LastActivity.After(users[j].activity.LastActivity) {
					users[i], users[j] = users[j], users[i]
				}
			}
		}

		// Remove oldest users
		toRemove := len(rl.userActivity) - rl.config.MaxUserHistory
		for i := 0; i < toRemove && i < len(users); i++ {
			delete(rl.userActivity, users[i].username)
			removedUsers++
		}
	}

	rl.stats.mu.Lock()
	rl.stats.CleanupRuns++
	rl.stats.LastCleanup = now
	rl.stats.mu.Unlock()

	log.Info("Cleanup completed",
		"removedUsers", removedUsers,
		"remainingUsers", len(rl.userActivity),
		"maxUsers", rl.config.MaxUserHistory)
}

// Stop stops the cleanup routine
func (rl *EnhancedRateLimiter) Stop() {
	close(rl.stopChan)
}

type EnhancedIngressPodProtectionWebhook struct {
	s           runtime.Scheme
	rateLimiter *EnhancedRateLimiter
}

// NewEnhancedWebhook creates the new enhanced webhook
func NewEnhancedWebhook() *EnhancedIngressPodProtectionWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to EnhancedIngressPodProtectionWebhook")
		os.Exit(1)
	}
	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to EnhancedIngressPodProtectionWebhook")
		os.Exit(1)
	}

	// Create rate limiter with default config
	rateLimiter := NewEnhancedRateLimiter(DefaultRateLimitConfig())

	return &EnhancedIngressPodProtectionWebhook{
		s:           *scheme,
		rateLimiter: rateLimiter,
	}
}

// Authorized implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *EnhancedIngressPodProtectionWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Check if this is a DELETE operation
	if request.Operation != admissionv1.Delete {
		ret = admissionctl.Allowed("Non-delete operations are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if the request is for pods in the openshift-ingress namespace
	if request.Namespace != enhancedTargetNamespace {
		ret = admissionctl.Allowed("Pods outside openshift-ingress namespace are not protected")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if user is authenticated
	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		enhancedLog.Info("system:unauthenticated made a webhook request. Check RBAC rules", "request", request.AdmissionRequest)
		ret = admissionctl.Denied("Unauthenticated")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Allow system users (except system:unauthenticated)
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "system:") && request.AdmissionRequest.UserInfo.Username != "system:unauthenticated" {
		ret = admissionctl.Allowed("System users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Allow kube: users
	if strings.HasPrefix(request.AdmissionRequest.UserInfo.Username, "kube:") {
		ret = admissionctl.Allowed("kube: users are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if user/group is explicitly allowed
	if isEnhancedAllowedUserGroup(request) {
		ret = admissionctl.Allowed("User/group is explicitly allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Enhanced rate limiting to detect bulk deletion patterns
	if s.rateLimiter.IsBulkDeletionAttempt(request) {
		username := request.AdmissionRequest.UserInfo.Username
		status := s.rateLimiter.GetUserStatus(username)
		stats := s.rateLimiter.GetStats()

		enhancedLog.Info("Bulk deletion pattern detected",
			"namespace", enhancedTargetNamespace,
			"user", username,
			"status", status,
			"stats", stats)

		ret = admissionctl.Denied(fmt.Sprintf("Rate limit exceeded in %s namespace. %s. Please wait before attempting more deletions.",
			enhancedTargetNamespace, status))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Allow individual pod deletions
	ret = admissionctl.Allowed("Individual pod deletion is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// isEnhancedAllowedUserGroup checks if the user or group is allowed to perform the action
func isEnhancedAllowedUserGroup(request admissionctl.Request) bool {
	username := request.AdmissionRequest.UserInfo.Username

	// Check allowed users
	for _, allowedUser := range enhancedAllowedUsers {
		if username == allowedUser {
			return true
		}
	}

	// Check allowed groups
	for _, group := range enhancedAllowedGroups {
		for _, userGroup := range request.AdmissionRequest.UserInfo.Groups {
			if userGroup == group {
				return true
			}
		}
	}

	return false
}

// GetURI implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) GetURI() string {
	return "/" + EnhancedWebhookName
}

// Validate implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "Pod")
	valid = valid && (request.Namespace == enhancedTargetNamespace)

	return valid
}

// Name implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) Name() string {
	return EnhancedWebhookName
}

// FailurePolicy implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) Rules() []admissionregv1.RuleWithOperations {
	return enhancedRules
}

// ObjectSelector implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) ObjectSelector() *metav1.LabelSelector {
	// Target only pods in the openshift-ingress namespace
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{enhancedTargetNamespace},
			},
		},
	}
}

// SideEffects implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) TimeoutSeconds() int32 {
	return enhancedTimeout
}

// Doc implements Webhook interface
func (s *EnhancedIngressPodProtectionWebhook) Doc() string {
	return enhancedDocString
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *EnhancedIngressPodProtectionWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *EnhancedIngressPodProtectionWebhook) ClassicEnabled() bool { return true }

func (s *EnhancedIngressPodProtectionWebhook) HypershiftEnabled() bool { return true }

// GetRateLimiterStats returns current rate limiter statistics for monitoring
func (s *EnhancedIngressPodProtectionWebhook) GetRateLimiterStats() map[string]interface{} {
	return s.rateLimiter.GetStats()
}

// UpdateRateLimitConfig allows runtime configuration updates
func (s *EnhancedIngressPodProtectionWebhook) UpdateRateLimitConfig(config *RateLimitConfig) {
	// This would require stopping and restarting the rate limiter
	// For now, we'll just log the request
	log.Info("Rate limit config update requested", "config", config)
}
