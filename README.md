# Namespace DNS Policy

Don't forget to checkout Kubewarden's [official documentation](https://docs.kubewarden.io)
for more information about writing policies.

## Usage

This repository contains a working policy written in Go.

The policy looks at the `name` of a Kubernetes namespace and rejects the request
if the name is on a deny list.

The deny list is configurable by the user via the runtime settings of the policy, as a default the [IANA TLDs](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
are used.

The configuration of the policy is expressed via this structure:

```json
{
  "denied_toplevel_domains": [ "com", "de" ]
}
```
