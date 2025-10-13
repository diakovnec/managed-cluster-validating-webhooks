package ingresspodprotection

import (
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	admissionctl "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestIngressPodProtectionWebhook_Authorized(t *testing.T) {
	webhook := NewWebhook()

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
					Namespace: targetNamespace,
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
			name: "Deny bulk deletion attempt (no resource name)",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: targetNamespace,
					Name:      "", // Empty name indicates --all usage
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"test-group"},
					},
				},
			},
			expected: false,
		},
		{
			name: "Allow deletion by backplane-cluster-admin",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: targetNamespace,
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
					Namespace: targetNamespace,
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
					Namespace: targetNamespace,
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
					Namespace: targetNamespace,
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
					Namespace: targetNamespace,
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

func TestIngressPodProtectionWebhook_Validate(t *testing.T) {
	webhook := NewWebhook()

	tests := []struct {
		name     string
		request  admissionctl.Request
		expected bool
	}{
		{
			name: "Valid pod deletion request",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: targetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
				},
			},
			expected: true,
		},
		{
			name: "Invalid - wrong kind",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Service"},
					Namespace: targetNamespace,
					Name:      "test-service",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid - wrong namespace",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: "default",
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid - empty username",
			request: admissionctl.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
					Kind:      metav1.GroupVersionKind{Kind: "Pod"},
					Namespace: targetNamespace,
					Name:      "test-pod",
					UserInfo: authenticationv1.UserInfo{
						Username: "",
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := webhook.Validate(tt.request)
			if result != tt.expected {
				t.Errorf("Expected validation result %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIngressPodProtectionWebhook_Interface(t *testing.T) {
	webhook := NewWebhook()

	// Test basic interface methods
	if webhook.Name() != WebhookName {
		t.Errorf("Expected webhook name %s, got %s", WebhookName, webhook.Name())
	}

	if webhook.GetURI() != "/"+WebhookName {
		t.Errorf("Expected webhook URI /%s, got %s", WebhookName, webhook.GetURI())
	}

	if webhook.FailurePolicy() != admissionregv1.Ignore {
		t.Errorf("Expected failure policy Ignore, got %s", webhook.FailurePolicy())
	}

	if webhook.MatchPolicy() != admissionregv1.Equivalent {
		t.Errorf("Expected match policy Equivalent, got %s", webhook.MatchPolicy())
	}

	if webhook.TimeoutSeconds() != timeout {
		t.Errorf("Expected timeout %d, got %d", timeout, webhook.TimeoutSeconds())
	}

	if webhook.SideEffects() != admissionregv1.SideEffectClassNone {
		t.Errorf("Expected side effects None, got %s", webhook.SideEffects())
	}

	if webhook.Doc() != docString {
		t.Errorf("Expected doc string %s, got %s", docString, webhook.Doc())
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
