variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "prefix" {
  description = "Globally unique short lowercase prefix (e.g. comuni-itn-001)"
  type        = string
  default     = "comuni-itn-001"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{3,17}$", var.prefix))
    error_message = "prefix must be 4-18 lowercase alphanumeric/hyphen characters."
  }
}

variable "location" {
  description = "Azure region; validate service availability and data residency before production."
  type        = string
  default     = "italynorth"
}

variable "postgres_admin_password" {
  description = "Administrative PostgreSQL credential; never store in Git or plaintext tfvars."
  type        = string
  sensitive   = true
}

variable "authentication_authority" {
  description = "Trusted OIDC issuer base URL (HTTPS) for JWT validation; must be provisioned separately."
  type        = string
  validation {
    condition     = startswith(var.authentication_authority, "https://")
    error_message = "authentication_authority must be an HTTPS URL."
  }
}

variable "authentication_audience" {
  description = "API resource audience expected in trusted OIDC access tokens."
  type        = string
  validation {
    condition     = length(trimspace(var.authentication_audience)) > 0
    error_message = "authentication_audience must not be empty."
  }
}

variable "image" {
  description = "Fully qualified immutable container image, e.g. registry.azurecr.io/comuni:<commit-sha>"
  type        = string
}

variable "tags" {
  type = map(string)
  default = {
    project     = "Comuni"
    managed_by  = "Terraform"
    environment = "development"
  }
}
