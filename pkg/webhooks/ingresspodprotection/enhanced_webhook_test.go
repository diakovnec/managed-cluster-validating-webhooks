package ingresspodprotection

import (
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestEnhancedRateLimiter_BasicFunctionality(t *testing.T) {
	config := &RateLimitConfig{
		Window:          1 * time.Minute,
		MaxDeletions:    2,
		Cooldown:        2 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		MaxUserHistory:  10,
	}

	limiter := NewEnhancedRateLimiter(config)
	defer limiter.Stop()

	// Test basic request
	request := admissionctl.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: enhancedTargetNamespace,
			Name:      "test-pod-1",
			UserInfo: authenticationv1.UserInfo{
				Username: "test-user",
				Groups:   []string{"test-group"},
			},
		},
	}

	// First deletion should be allowed
	if limiter.IsBulkDeletionAttempt(request) {
		t.Error("First deletion should be allowed")
	}

	// Second deletion should be allowed
	if limiter.IsBulkDeletionAttempt(request) {
		t.Error("Second deletion should be allowed")
	}

	// Third deletion should be blocked
	if !limiter.IsBulkDeletionAttempt(request) {
		t.Error("Third deletion should be blocked")
	}

	// Check user status
	status := limiter.GetUserStatus("test-user")
	if !strings.Contains(status, "Blocked until") {
		t.Errorf("Expected blocked status, got: %s", status)
	}
}

func TestEnhancedRateLimiter_TimeWindow(t *testing.T) {
	config := &RateLimitConfig{
		Window:          100 * time.Millisecond, // Very short window for testing
		MaxDeletions:    2,
		Cooldown:        1 * time.Second,
		CleanupInterval: 5 * time.Minute,
		MaxUserHistory:  10,
	}

	limiter := NewEnhancedRateLimiter(config)
	defer limiter.Stop()

	request := admissionctl.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: enhancedTargetNamespace,
			Name:      "test-pod",
			UserInfo: authenticationv1.UserInfo{
				Username: "test-user",
			},
		},
	}

	// Make 2 deletions (should be allowed)
	for i := 0; i < 2; i++ {
		if limiter.IsBulkDeletionAttempt(request) {
			t.Errorf("Deletion %d should be allowed", i+1)
		}
	}

	// Third deletion should be blocked
	if !limiter.IsBulkDeletionAttempt(request) {
		t.Error("Third deletion should be blocked")
	}

	// Wait for cooldown to expire (cooldown is 1 second)
	time.Sleep(1100 * time.Millisecond)

	// After cooldown expires, should be allowed again
	if limiter.IsBulkDeletionAttempt(request) {
		t.Error("Deletion after cooldown expiry should be allowed")
	}
}

func TestEnhancedRateLimiter_Cleanup(t *testing.T) {
	config := &RateLimitConfig{
		Window:          1 * time.Minute,
		MaxDeletions:    2,
		Cooldown:        2 * time.Minute,
		CleanupInterval: 100 * time.Millisecond, // Very frequent cleanup for testing
		MaxUserHistory:  2,                      // Very small limit for testing
	}

	limiter := NewEnhancedRateLimiter(config)
	defer limiter.Stop()

	// Create multiple users
	users := []string{"user1", "user2", "user3", "user4"}
	for _, user := range users {
		request := admissionctl.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Delete,
				Kind:      metav1.GroupVersionKind{Kind: "Pod"},
				Namespace: enhancedTargetNamespace,
				Name:      "test-pod",
				UserInfo: authenticationv1.UserInfo{
					Username: user,
				},
			},
		}
		limiter.IsBulkDeletionAttempt(request)
	}

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Check that cleanup happened
	stats := limiter.GetStats()
	if stats["cleanupRuns"].(int64) == 0 {
		t.Error("Expected cleanup to have run")
	}
}

func TestEnhancedIngressPodProtectionWebhook_Authorized(t *testing.T) {
	webhook := NewEnhancedWebhook()
	defer webhook.rateLimiter.Stop()

	tests := []struct {
		name     string
		request  admissionctl.Request
		expected bool // true if allowed, false if denied
	}{
		{
			name: "Allow individual pod deletion by regular user",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"test-group"},
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{"metadata":{"name":"test-pod","namespace":"openshift-ingress"}}`),
					},
				},
			},
			expected: true,
		},
		{
			name: "Allow deletion by backplane-cluster-admin",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "backplane-cluster-admin",
						Groups:   []string{},
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{"metadata":{"name":"test-pod","namespace":"openshift-ingress"}}`),
					},
				},
			},
			expected: true,
		},
		{
			name: "Allow deletion by system:admin",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "system:admin",
						Groups:   []string{},
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{"metadata":{"name":"test-pod","namespace":"openshift-ingress"}}`),
					},
				},
			},
			expected: true,
		},
		{
			name: "Allow deletion by allowed group",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"system:serviceaccounts:openshift-backplane-srep"},
					},
					OldObject: runtime.RawExtension{
						Raw: []byte(`{"metadata":{"name":"test-pod","namespace":"openshift-ingress"}}`),
					},
				},
			},
			expected: true,
		},
		{
			name: "Allow non-delete operations",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"test-group"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Allow operations outside openshift-ingress namespace",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: "default",
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"test-group"},
					},
				},
			},
			expected: true,
		},
		{
			name: "Deny unauthenticated requests",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: enhancedTargetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "system:unauthenticated",
						Groups:   []string{},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := webhook.Authorized(tt.request)

			if tt.expected && !response.Allowed {
				t.Errorf("Expected request to be allowed, but it was denied: %s", response.Result.Message)
			}
			if !tt.expected && response.Allowed {
				t.Errorf("Expected request to be denied, but it was allowed")
			}
		})
	}
}

func TestEnhancedIngressPodProtectionWebhook_RateLimiting(t *testing.T) {
	webhook := NewEnhancedWebhook()
	defer webhook.rateLimiter.Stop()

	// Create a request that will trigger rate limiting
	request := admissionctl.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Delete,
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: enhancedTargetNamespace,
			Name:      "test-pod",
			UserInfo: authenticationv1.UserInfo{
				Username: "rate-limit-test-user",
				Groups:   []string{"test-group"},
			},
			OldObject: runtime.RawExtension{
				Raw: []byte(`{"metadata":{"name":"test-pod","namespace":"openshift-ingress"}}`),
			},
		},
	}

	// Make multiple requests to trigger rate limiting
	responses := make([]admissionctl.Response, 5)
	for i := 0; i < 5; i++ {
		responses[i] = webhook.Authorized(request)
	}

	// Check that some requests were blocked due to rate limiting
	blockedCount := 0
	for _, resp := range responses {
		if !resp.Allowed {
			blockedCount++
		}
	}

	if blockedCount == 0 {
		t.Error("Expected some requests to be blocked by rate limiting")
	}

	// Check stats
	stats := webhook.GetRateLimiterStats()
	if stats["totalRequests"].(int64) != 5 {
		t.Errorf("Expected 5 total requests, got %d", stats["totalRequests"])
	}
}

func TestEnhancedIngressPodProtectionWebhook_Interface(t *testing.T) {
	webhook := NewEnhancedWebhook()
	defer webhook.rateLimiter.Stop()

	// Test basic interface methods
	if webhook.Name() != EnhancedWebhookName {
		t.Errorf("Expected webhook name %s, got %s", EnhancedWebhookName, webhook.Name())
	}

	if webhook.GetURI() != "/"+EnhancedWebhookName {
		t.Errorf("Expected webhook URI /%s, got %s", EnhancedWebhookName, webhook.GetURI())
	}

	if webhook.FailurePolicy() != admissionregv1.Ignore {
		t.Errorf("Expected failure policy Ignore, got %s", webhook.FailurePolicy())
	}

	if webhook.MatchPolicy() != admissionregv1.Equivalent {
		t.Errorf("Expected match policy Equivalent, got %s", webhook.MatchPolicy())
	}

	if webhook.TimeoutSeconds() != enhancedTimeout {
		t.Errorf("Expected timeout %d, got %d", enhancedTimeout, webhook.TimeoutSeconds())
	}

	if webhook.SideEffects() != admissionregv1.SideEffectClassNone {
		t.Errorf("Expected side effects None, got %s", webhook.SideEffects())
	}

	if webhook.Doc() != enhancedDocString {
		t.Errorf("Expected doc string %s, got %s", enhancedDocString, webhook.Doc())
	}

	if !webhook.ClassicEnabled() {
		t.Error("Expected ClassicEnabled to be true")
	}

	if !webhook.HypershiftEnabled() {
		t.Error("Expected HypershiftEnabled to be true")
	}

	// Test rules
	rules := webhook.Rules()
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}

	if len(rules[0].Operations) != 1 || rules[0].Operations[0] != admissionregv1.Delete {
		t.Errorf("Expected DELETE operation, got %v", rules[0].Operations)
	}

	// Test object selector
	selector := webhook.ObjectSelector()
	if selector == nil {
		t.Error("Expected object selector to be set")
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	if config.Window != 2*time.Minute {
		t.Errorf("Expected window 2m, got %v", config.Window)
	}

	if config.MaxDeletions != 3 {
		t.Errorf("Expected max deletions 3, got %d", config.MaxDeletions)
	}

	if config.Cooldown != 5*time.Minute {
		t.Errorf("Expected cooldown 5m, got %v", config.Cooldown)
	}

	if config.CleanupInterval != 10*time.Minute {
		t.Errorf("Expected cleanup interval 10m, got %v", config.CleanupInterval)
	}

	if config.MaxUserHistory != 1000 {
		t.Errorf("Expected max user history 1000, got %d", config.MaxUserHistory)
	}
}
