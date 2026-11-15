output "application_url" {
  description = "Public URL of the single API and React PWA"
  value       = "https://${azurerm_container_app.main.latest_revision_fqdn}"
}

output "acr_name" {
  value = azurerm_container_registry.main.name
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.main.fqdn
}

output "identity_client_id" {
  value = azurerm_user_assigned_identity.app.client_id
}
