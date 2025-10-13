package ingresspodprotection

import (
	"fmt"
	"os"
	"strings"

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
	WebhookName     string = "ingress-pod-protection"
	targetNamespace string = "openshift-ingress"
	docString       string = `Managed OpenShift Customers may not delete all pods at once in the openshift-ingress namespace using --all or -l selectors to prevent service disruption.`
)

var (
	timeout int32 = 2
	log           = logf.Log.WithName(WebhookName)
	scope         = admissionregv1.NamespacedScope
	rules         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{"DELETE"},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &scope,
			},
		},
	}

	// Users allowed to delete pods in openshift-ingress namespace
	allowedUsers = []string{
		"backplane-cluster-admin",
		"system:admin",
	}

	// Groups allowed to delete pods in openshift-ingress namespace
	allowedGroups = []string{
		"system:serviceaccounts:openshift-backplane-srep",
		"system:serviceaccounts:openshift-ingress-operator",
	}
)

type IngressPodProtectionWebhook struct {
	s runtime.Scheme
}

// NewWebhook creates the new webhook
func NewWebhook() *IngressPodProtectionWebhook {
	scheme := runtime.NewScheme()
	err := admissionv1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding admissionsv1 scheme to IngressPodProtectionWebhook")
		os.Exit(1)
	}
	err = corev1.AddToScheme(scheme)
	if err != nil {
		log.Error(err, "Fail adding corev1 scheme to IngressPodProtectionWebhook")
		os.Exit(1)
	}

	return &IngressPodProtectionWebhook{
		s: *scheme,
	}
}

// Authorized implements Webhook interface
func (s *IngressPodProtectionWebhook) Authorized(request admissionctl.Request) admissionctl.Response {
	return s.authorized(request)
}

func (s *IngressPodProtectionWebhook) authorized(request admissionctl.Request) admissionctl.Response {
	var ret admissionctl.Response

	// Check if this is a DELETE operation
	if request.Operation != admissionv1.Delete {
		ret = admissionctl.Allowed("Non-delete operations are allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if the request is for pods in the openshift-ingress namespace
	if request.Namespace != targetNamespace {
		ret = admissionctl.Allowed("Pods outside openshift-ingress namespace are not protected")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if user is authenticated
	if request.AdmissionRequest.UserInfo.Username == "system:unauthenticated" {
		log.Info("system:unauthenticated made a webhook request. Check RBAC rules", "request", request.AdmissionRequest)
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
	if isAllowedUserGroup(request) {
		ret = admissionctl.Allowed("User/group is explicitly allowed")
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Check if this is a bulk deletion attempt
	if isBulkDeletionAttempt(request) {
		log.Info(fmt.Sprintf("Bulk deletion attempt detected in %s namespace by user: %s", targetNamespace, request.AdmissionRequest.UserInfo.Username))
		ret = admissionctl.Denied(fmt.Sprintf("Bulk deletion of pods in %s namespace is not allowed. Use specific pod names instead of --all or -l selectors.", targetNamespace))
		ret.UID = request.AdmissionRequest.UID
		return ret
	}

	// Allow individual pod deletions
	ret = admissionctl.Allowed("Individual pod deletion is allowed")
	ret.UID = request.AdmissionRequest.UID
	return ret
}

// isBulkDeletionAttempt checks if the request is attempting to delete multiple pods
// This includes --all flag or -l selector usage
func isBulkDeletionAttempt(request admissionctl.Request) bool {
	// Check if the request is missing specific resource name (indicates --all usage)
	// When using --all, the request might not have a specific resource name
	if request.Name == "" {
		log.Info("Request missing resource name, likely --all operation")
		return true
	}

	// Check if the request has a label selector in the raw request
	// This is a heuristic - kubectl with -l will include selector information
	if len(request.AdmissionRequest.OldObject.Raw) == 0 {
		// If there's no old object but we're deleting, it might be a bulk operation
		log.Info("No old object in delete request, possible bulk operation")
		return true
	}

	return false
}

// isAllowedUserGroup checks if the user or group is allowed to perform the action
func isAllowedUserGroup(request admissionctl.Request) bool {
	username := request.AdmissionRequest.UserInfo.Username

	// Check allowed users
	for _, allowedUser := range allowedUsers {
		if username == allowedUser {
			return true
		}
	}

	// Check allowed groups
	for _, group := range allowedGroups {
		for _, userGroup := range request.AdmissionRequest.UserInfo.Groups {
			if userGroup == group {
				return true
			}
		}
	}

	return false
}

// GetURI implements Webhook interface
func (s *IngressPodProtectionWebhook) GetURI() string {
	return "/" + WebhookName
}

// Validate implements Webhook interface
func (s *IngressPodProtectionWebhook) Validate(request admissionctl.Request) bool {
	valid := true
	valid = valid && (request.UserInfo.Username != "")
	valid = valid && (request.Kind.Kind == "Pod")
	valid = valid && (request.Namespace == targetNamespace)

	return valid
}

// Name implements Webhook interface
func (s *IngressPodProtectionWebhook) Name() string {
	return WebhookName
}

// FailurePolicy implements Webhook interface
func (s *IngressPodProtectionWebhook) FailurePolicy() admissionregv1.FailurePolicyType {
	return admissionregv1.Ignore
}

// MatchPolicy implements Webhook interface
func (s *IngressPodProtectionWebhook) MatchPolicy() admissionregv1.MatchPolicyType {
	return admissionregv1.Equivalent
}

// Rules implements Webhook interface
func (s *IngressPodProtectionWebhook) Rules() []admissionregv1.RuleWithOperations {
	return rules
}

// ObjectSelector implements Webhook interface
func (s *IngressPodProtectionWebhook) ObjectSelector() *metav1.LabelSelector {
	// Target only pods in the openshift-ingress namespace
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{targetNamespace},
			},
		},
	}
}

// SideEffects implements Webhook interface
func (s *IngressPodProtectionWebhook) SideEffects() admissionregv1.SideEffectClass {
	return admissionregv1.SideEffectClassNone
}

// TimeoutSeconds implements Webhook interface
func (s *IngressPodProtectionWebhook) TimeoutSeconds() int32 {
	return timeout
}

// Doc implements Webhook interface
func (s *IngressPodProtectionWebhook) Doc() string {
	return docString
}

// SyncSetLabelSelector returns the label selector to use in the SyncSet.
// Return utils.DefaultLabelSelector() to stick with the default
func (s *IngressPodProtectionWebhook) SyncSetLabelSelector() metav1.LabelSelector {
	return utils.DefaultLabelSelector()
}

func (s *IngressPodProtectionWebhook) ClassicEnabled() bool { return true }

func (s *IngressPodProtectionWebhook) HypershiftEnabled() bool { return true }
