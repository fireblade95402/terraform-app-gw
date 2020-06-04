#outputs.tf
output "object" {
  value = azurerm_web_application_firewall_policy.app-gw-policy
}

output "waf-map" {
  value = {
    for waf in azurerm_web_application_firewall_policy.app-gw-policy:
    waf.name => waf.id

  }
}
