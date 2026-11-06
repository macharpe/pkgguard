output "admin_aud" {
  description = "Audience tag of the admin application. The admin Worker verifies Cf-Access-Jwt-Assertion against it."
  value       = cloudflare_zero_trust_access_application.admin.aud
}

output "service_token_client_id" {
  description = "CF-Access-Client-Id for the API service token."
  value       = cloudflare_zero_trust_access_service_token.api.client_id
}

output "service_token_client_secret" {
  description = "CF-Access-Client-Secret as created. Goes stale after a rotation in the dashboard, because the provider does not track it: the password manager is the source of truth."
  value       = cloudflare_zero_trust_access_service_token.api.client_secret
  sensitive   = true
}
