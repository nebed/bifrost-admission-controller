# bifrost-admission-controller
An intended general-purpose admission controller

## Current Feature
- generate the `ca.crt` field from full chain certificate in `tls.crt` and append to the secret for ACME issued certificates

## Operation
The admission controller contains a helm template that can be installed on kubernetes clusters
It creates the MutatingWebhookConfiguration from within the Go code, hence it needs create and
update permissions on the MutatingWebhookConfiguration resource.

The default MutatingWebhookConfiguration has a namespace selector and only watches namespaces with label
`acme-tls-update=enabled`

Also when creating cert-manager certificate resources we need to set the SecretTemplate to have an annotation
`bifrost-acme-update-webhook.nebed.io/update=true`
```
  secretTemplate:
    annotations:
      bifrost-acme-update-webhook.nebed.io/update: "true"
```
