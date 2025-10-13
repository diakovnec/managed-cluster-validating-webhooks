# Ingress Pod Protection Webhook

## Overview

The Ingress Pod Protection Webhook (`ingress-pod-protection`) is designed to prevent bulk deletion of pods in the `openshift-ingress` namespace. This protection helps prevent accidental service disruption by blocking operations that could delete all ingress pods at once.

## Protection Scope

The webhook specifically targets:
- **Namespace**: `openshift-ingress`
- **Resource**: `pods`
- **Operation**: `DELETE`
- **Bulk Operations**: Blocks `--all` and `-l` selector deletions

## Allowed Operations

The following operations are **allowed**:
- Individual pod deletions by name
- Deletions by privileged users (`backplane-cluster-admin`, `system:admin`)
- Deletions by privileged groups (`system:serviceaccounts:openshift-backplane-srep`, `system:serviceaccounts:openshift-ingress-operator`)
- Non-delete operations (CREATE, UPDATE)
- Operations outside the `openshift-ingress` namespace

## Blocked Operations

The following operations are **blocked**:
- Bulk deletions using `--all` flag
- Bulk deletions using `-l` selectors
- Unauthenticated requests
- Bulk deletions by regular users

## Examples

### Allowed Commands
```bash
# Delete specific pod
kubectl delete pod router-1-abc123 -n openshift-ingress

# Delete by backplane admin (always allowed)
kubectl delete pods --all -n openshift-ingress --as=backplane-cluster-admin
```

### Blocked Commands
```bash
# These will be blocked for regular users:
kubectl delete pods --all -n openshift-ingress
kubectl delete pods -l app=router -n openshift-ingress
```

## Error Messages

When a bulk deletion is blocked, users will see:
```
Bulk deletion of pods in openshift-ingress namespace is not allowed. Use specific pod names instead of --all or -l selectors.
```

## Implementation Details

The webhook uses several heuristics to detect bulk deletion attempts:
1. **Missing resource name**: Indicates `--all` usage
2. **Empty old object**: Suggests bulk operation
3. **Label selector patterns**: Detects `-l` usage

## Configuration

The webhook is configured with:
- **Failure Policy**: `Ignore` (to prevent blocking legitimate operations if webhook fails)
- **Match Policy**: `Equivalent`
- **Timeout**: 2 seconds
- **Side Effects**: `None`
- **Scope**: `Namespaced`

## Testing

Run the test suite with:
```bash
go test ./pkg/webhooks/ingresspodprotection/... -v
```

The test suite covers:
- Individual pod deletion scenarios
- Bulk deletion detection
- Privileged user/group access
- Validation logic
- Interface compliance

