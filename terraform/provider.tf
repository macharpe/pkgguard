# The token arrives as TF_VAR_cloudflare_api_token from a gitignored .envrc.
# Never use the bare CLOUDFLARE_API_TOKEN name: wrangler reserves it and would abandon its OAuth session.
provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
