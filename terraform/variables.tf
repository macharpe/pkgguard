variable "cloudflare_api_token" {
  description = "API token with Access edit and Zero Trust edit on the account. Supplied as TF_VAR_cloudflare_api_token."
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account that owns the Access applications."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be 32 lowercase hex characters."
  }
}

variable "admin_hostname" {
  description = "Hostname of the PkgGuard admin UI, for example pkgguard.example.com."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.admin_hostname))
    error_message = "admin_hostname must be a dotted lowercase hostname with no scheme or path."
  }
}

variable "allowed_idp_ids" {
  description = "Identity provider IDs offered on the login page."
  type        = list(string)

  validation {
    condition     = length(var.allowed_idp_ids) > 0 && alltrue([for id in var.allowed_idp_ids : can(regex("^[0-9a-f-]{36}$", id))])
    error_message = "allowed_idp_ids must hold at least one identity provider UUID."
  }
}

variable "human_access_policy_ids" {
  description = "Existing reusable Access policy IDs that admit people, in evaluation order. They are referenced, never created or modified here."
  type        = list(string)

  validation {
    condition     = length(var.human_access_policy_ids) > 0 && alltrue([for id in var.human_access_policy_ids : can(regex("^[0-9a-f-]{36}$", id))])
    error_message = "human_access_policy_ids must hold at least one policy UUID."
  }
}

variable "session_duration" {
  description = "How long a browser session on the admin UI lasts."
  type        = string
  default     = "24h"
}

variable "service_token_duration" {
  description = "Lifetime of the API service token. Rotate before it expires."
  type        = string
  default     = "8760h"
}
