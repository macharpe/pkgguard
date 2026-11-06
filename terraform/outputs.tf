output "admin_ui_aud" {
  description = "Audience tag of the admin UI application. The admin Worker verifies Cf-Access-Jwt-Assertion against it."
  value       = cloudflare_zero_trust_access_application.admin_ui.aud
}

output "admin_api_aud" {
  description = "Audience tag of the admin API application."
  value       = cloudflare_zero_trust_access_application.admin_api.aud
}

output "service_token_client_id" {
  description = "CF-Access-Client-Id for the API service token."
  value       = cloudflare_zero_trust_access_service_token.api.client_id
}

output "service_token_client_secret" {
  description = "CF-Access-Client-Secret for the API service token. Store it in a password manager; it is shown only by `terraform output`."
  value       = cloudflare_zero_trust_access_service_token.api.client_secret
  sensitive   = true
}
