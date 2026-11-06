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

# One application for the whole hostname. A second application on /api/* would share this hostname's
# CF_Authorization cookie name but have a different audience, so a browser session earned on the dashboard
# is rejected on /api/* and the dashboard's own fetch() calls bounce to login. People and the service token
# therefore share one application and one audience. The Worker, not Access, keeps the token to /api/*.
resource "cloudflare_zero_trust_access_application" "admin" {
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

  policies = concat(local.human_policies, [{
    id         = cloudflare_zero_trust_access_policy.api_service_token.id
    precedence = local.service_token_policy_precedence
  }])

  lifecycle {
    prevent_destroy = true
  }
}

# The dashboard application used to be named admin_ui, and a second application, admin_api, covered /api/*.
moved {
  from = cloudflare_zero_trust_access_application.admin_ui
  to   = cloudflare_zero_trust_access_application.admin
}
