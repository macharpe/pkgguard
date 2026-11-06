locals {
  # Every policy is attached with an explicit precedence so evaluation order is never implicit.
  human_policies = [
    for index, id in var.human_access_policy_ids : {
      id         = id
      precedence = index + 1
    }
  ]

  service_token_policy_precedence = length(var.human_access_policy_ids) + 1
}

resource "cloudflare_zero_trust_access_service_token" "api" {
  account_id = var.cloudflare_account_id
  name       = "pkgguard-admin-api"
  duration   = var.service_token_duration

  lifecycle {
    prevent_destroy = true
  }
}

resource "cloudflare_zero_trust_access_policy" "api_service_token" {
  account_id = var.cloudflare_account_id
  name       = "PkgGuard API Service Token Policy"
  decision   = "non_identity"

  include = [{
    service_token = {
      token_id = cloudflare_zero_trust_access_service_token.api.id
    }
  }]
}

# The dashboard: people only.
resource "cloudflare_zero_trust_access_application" "admin_ui" {
  account_id           = var.cloudflare_account_id
  type                 = "self_hosted"
  name                 = "PkgGuard Admin"
  app_launcher_visible = true
  session_duration     = var.session_duration

  destinations = [{
    type = "public"
    uri  = var.admin_hostname
  }]

  allowed_idps              = var.allowed_idp_ids
  auto_redirect_to_identity = false # two identity providers: let the user choose

  policies = local.human_policies

  lifecycle {
    prevent_destroy = true
  }
}

# The API path is a more specific application, so it wins over the dashboard for /api/*.
# It must admit people as well as the service token: the dashboard's own fetch() calls
# to /api/* carry the browser session and would be denied by a token-only policy.
resource "cloudflare_zero_trust_access_application" "admin_api" {
  account_id           = var.cloudflare_account_id
  type                 = "self_hosted"
  name                 = "PkgGuard Admin API"
  app_launcher_visible = false
  session_duration     = var.session_duration

  destinations = [{
    type = "public"
    uri  = "${var.admin_hostname}/api/*"
  }]

  allowed_idps              = var.allowed_idp_ids
  auto_redirect_to_identity = false

  policies = concat(local.human_policies, [{
    id         = cloudflare_zero_trust_access_policy.api_service_token.id
    precedence = local.service_token_policy_precedence
  }])

  lifecycle {
    prevent_destroy = true
  }
}
