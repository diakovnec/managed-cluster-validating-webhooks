package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/ingresspodprotection"
)

func init() {
	Register(ingresspodprotection.EnhancedWebhookName, func() Webhook { return ingresspodprotection.NewEnhancedWebhook() })
}
