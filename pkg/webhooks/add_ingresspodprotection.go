package webhooks

import (
	"github.com/openshift/managed-cluster-validating-webhooks/pkg/webhooks/ingresspodprotection"
)

func init() {
	Register(ingresspodprotection.WebhookName, func() Webhook { return ingresspodprotection.NewWebhook() })
}

