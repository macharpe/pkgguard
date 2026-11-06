# PkgGuard Terraform

Manages the Cloudflare Access side of PkgGuard:

| Resource | Purpose |
|---|---|
| `cloudflare_zero_trust_access_application.admin` | The whole admin hostname: dashboard and `/api/*`. People through existing reusable policies, plus the service token. |
| `cloudflare_zero_trust_access_policy.api_service_token` | `non_identity` policy admitting the API service token. |
| `cloudflare_zero_trust_access_service_token.api` | The token for scripted access to `/api/*`. |

There is deliberately **one** application. A second one on `/api/*` shares the hostname's `CF_Authorization` cookie name with a different audience, so a browser session earned on the dashboard is rejected on the API. Access cannot keep the token to `/api/*` inside a single application, so the admin Worker does: it refuses a service-token identity on any other path.

The existing reusable policies and identity providers are referenced by ID and never modified.

## Not managed here

- **The Gateway Forward rule.** The provider (5.28.x) has no `forward` action, so `scripts/gateway-rule.ts` manages it through the API. Move it into Terraform, with an import, once the provider supports it.
- Workers, D1, KV and the Workflow, which stay in wrangler.

## Use

```bash
cp terraform.tfvars.example terraform.tfvars   # then fill in real IDs; the file is gitignored
export TF_VAR_cloudflare_api_token=...          # Access edit + Zero Trust edit on the account
export TF_VAR_cloudflare_account_id=...

terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
```

Never apply without reading the plan. State is local and gitignored; it holds the service token secret, so treat the directory as sensitive.

The Access application and the service token carry `prevent_destroy`. Do not use the bare `CLOUDFLARE_API_TOKEN` name: wrangler reserves it.
