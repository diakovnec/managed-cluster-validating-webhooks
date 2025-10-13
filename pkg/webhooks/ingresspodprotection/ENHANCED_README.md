# Enhanced Ingress Pod Protection Webhook

## Overview

The Enhanced Ingress Pod Protection Webhook (`ingress-pod-protection-enhanced`) provides sophisticated protection against bulk pod deletion in the `openshift-ingress` namespace using **rate limiting** and **pattern detection**. This webhook addresses the fundamental challenge of detecting bulk operations at the API server level.

## Key Features

### 🚀 **Enhanced Rate Limiting**
- **Configurable time windows** for rate limiting
- **Per-user tracking** with automatic cleanup
- **Cooldown periods** after limit violations
- **Memory management** to prevent leaks

### 📊 **Comprehensive Monitoring**
- **Real-time statistics** tracking
- **Detailed logging** of all activities
- **User activity monitoring** with block counts
- **Performance metrics** for operations

### 🛡️ **Robust Protection**
- **Pattern detection** for bulk deletion attempts
- **Privileged user bypass** for legitimate operations
- **System user protection** (system:, kube: users)
- **Fail-safe design** with Ignore failure policy

## Configuration

### Default Configuration
```go
RateLimitConfig{
    Window:         2 * time.Minute,  // Rate limiting window
    MaxDeletions:   1,                // Max 1 deletion per window (openshift-ingress typically has 2 pods)
    Cooldown:      5 * time.Minute,  // Block duration after limit
    CleanupInterval: 10 * time.Minute, // Memory cleanup frequency
    MaxUserHistory: 1000,            // Max users to track
}
```

**Rationale**: The `openshift-ingress` namespace typically contains only **2 router pods**. Setting `MaxDeletions: 1` means:
- ✅ Individual pod deletion is allowed
- ❌ Rapid deletion of both pods (bulk operation) is blocked
- ✅ Legitimate rolling updates require 2-minute wait between deletions or use of proper tools (`oc rollout restart`)

### Custom Configuration
```go
config := &RateLimitConfig{
    Window:         1 * time.Minute,  // Shorter window
    MaxDeletions:   2,                // Stricter limit
    Cooldown:      10 * time.Minute, // Longer cooldown
    CleanupInterval: 5 * time.Minute, // More frequent cleanup
    MaxUserHistory: 500,              // Smaller user limit
}
```

## How It Works

### 1. **Request Processing Flow**
```
Request → Operation Check → Namespace Check → Authentication → 
User Type Check → Rate Limiting → Decision
```

### 2. **Rate Limiting Logic**
- **Track deletions** per user within time window
- **Block users** who exceed the limit
- **Apply cooldown** period after blocking
- **Clean up** old data automatically

### 3. **Memory Management**
- **Automatic cleanup** of inactive users
- **Configurable limits** on tracked users
- **Background goroutine** for maintenance
- **Graceful shutdown** support

## Usage Examples

### ✅ **Allowed Operations**
```bash
# Individual pod deletion
oc delete pod router-1-abc123 -n openshift-ingress

# Privileged user operations
oc delete pods --all -n openshift-ingress --as=backplane-cluster-admin

# System user operations
oc delete pod router-1-abc123 -n openshift-ingress --as=system:admin
```

### ❌ **Blocked Operations**
```bash
# Bulk deletion by regular user (exceeds rate limit)
oc delete pods --all -n openshift-ingress
# First pod deleted successfully, second pod blocked!

oc delete pods -l app=router -n openshift-ingress
# First pod deleted successfully, second pod blocked!

# Rapid individual deletions (exceeds rate limit)
oc delete pod pod1 -n openshift-ingress  # Allowed
oc delete pod pod2 -n openshift-ingress  # BLOCKED! (within 2-minute window)
```

**Important**: Since openshift-ingress typically has only 2 pods, this configuration effectively blocks bulk deletion attempts while still allowing individual pod management.

## Error Messages

### Rate Limit Exceeded
```
Rate limit exceeded in openshift-ingress namespace. 
Blocked until 2024-01-15 14:30:00 (total blocks: 1). 
Please wait before attempting more deletions.
```

### User Status Examples
```
# Active user
"Active deletions: 2 (total blocks: 0)"

# Blocked user
"Blocked until 2024-01-15 14:30:00 (total blocks: 1)"

# New user
"No activity"
```

## Monitoring & Statistics

### Available Metrics
```go
stats := webhook.GetRateLimiterStats()
// Returns:
{
    "totalRequests":   150,
    "allowedRequests":  120,
    "blockedRequests":  30,
    "activeUsers":      25,
    "cleanupRuns":      5,
    "lastCleanup":      "2024-01-15T14:25:00Z"
}
```

### Logging Examples
```
INFO Bulk deletion pattern detected namespace=openshift-ingress user=test-user status="Blocked until 2024-01-15 14:30:00" stats=map[totalRequests:5 blockedRequests:1]
INFO Cleanup completed removedUsers=5 remainingUsers=20 maxUsers=1000
INFO Rate limit exceeded user=test-user deletions=3 window=2m0s blockedUntil=2024-01-15 14:30:00 totalBlocks=1
```

## Implementation Details

### **Architecture Components**

1. **EnhancedRateLimiter**: Core rate limiting logic
2. **RateLimitConfig**: Configuration management
3. **UserActivity**: Per-user tracking
4. **RateLimitStats**: Statistics collection
5. **Cleanup Routine**: Background maintenance

### **Thread Safety**
- **RWMutex** for concurrent access
- **Atomic operations** for statistics
- **Channel-based** cleanup coordination

### **Performance Optimizations**
- **Efficient time calculations** with cutoff-based cleanup
- **Minimal memory allocation** with pre-sized slices
- **Background cleanup** to avoid blocking requests
- **Configurable limits** to prevent unbounded growth

## Testing

### Test Coverage
- ✅ **Basic functionality** testing
- ✅ **Time window** behavior
- ✅ **Cleanup routine** verification
- ✅ **Rate limiting** scenarios
- ✅ **Interface compliance** testing
- ✅ **Configuration** validation

### Run Tests
```bash
go test ./pkg/webhooks/ingresspodprotection/... -v
```

## Deployment

### Registration
The webhook is automatically registered as:
```go
Register("ingress-pod-protection-enhanced", NewEnhancedWebhook)
```

### Webhook Configuration
- **Name**: `ingress-pod-protection-enhanced`
- **URI**: `/ingress-pod-protection-enhanced`
- **Failure Policy**: `Ignore`
- **Match Policy**: `Equivalent`
- **Timeout**: 2 seconds
- **Side Effects**: `None`

## Limitations & Considerations

### **Known Limitations**
1. **Time-based bypass**: Users can wait between deletions
2. **User impersonation**: `--as` flag can bypass restrictions
3. **Distributed attacks**: Multiple users can coordinate
4. **Memory usage**: Tracks user activity in memory

### **Mitigation Strategies**
1. **Short windows**: Reduce bypass opportunities
2. **Privileged user controls**: Limit `--as` usage
3. **Monitoring**: Track patterns across users
4. **Memory limits**: Configurable user tracking limits

## Comparison with Basic Webhook

| Feature | Basic Webhook | Enhanced Webhook |
|---------|---------------|------------------|
| **Detection Method** | Heuristics | Rate Limiting |
| **Memory Management** | None | Automatic cleanup |
| **Statistics** | Basic logging | Comprehensive metrics |
| **Configuration** | Fixed | Fully configurable |
| **Performance** | Simple | Optimized |
| **Reliability** | Low | High |

## Best Practices

1. **Monitor statistics** regularly for tuning
2. **Set appropriate limits** based on usage patterns
3. **Use privileged users** for legitimate bulk operations
4. **Review logs** for security analysis
5. **Test configuration** changes in staging

This enhanced webhook provides a robust, production-ready solution for protecting against bulk pod deletion while maintaining operational flexibility and performance.

