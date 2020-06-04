resource "azurerm_web_application_firewall_policy" "app-gw-policy" {
  for_each                          = var.app-gw-waf-object
  name                              = each.value.name
  resource_group_name               = var.app-gw-rg
  location                          = var.location
  tags                              = var.tags
  
  dynamic "custom_rules" {
    for_each = each.value.custom_rules
    content {
      name     = custom_rules.value.name
      priority = custom_rules.value.priority
      rule_type     = custom_rules.value.rule_type
      action   = custom_rules.value.action
      dynamic "match_conditions" {
        for_each = custom_rules.value.match_conditions
        content {
           dynamic "match_variables" {
            for_each = match_conditions.value.match_variables
            content {
              variable_name = match_variables.value.variable_name
              selector =  match_variables.value.selector
            }
          }
          match_values       = match_conditions.value.match_values
          operator           = match_conditions.value.operator
          negation_condition = match_conditions.value.negation_condition
        }
      }
    }
  }
  dynamic "policy_settings" {
    for_each = [each.value.policy_settings]
    content {
      enabled                 =  policy_settings.value.enabled
      mode                    =  policy_settings.value.mode
    }
  }
  dynamic "managed_rules" {
    for_each = each.value.managed_rules
    content {
      dynamic "exclusion" {
        for_each = managed_rules.value.exclusion
        content {
          match_variable              = exclusion.value.match_variable
          selector_match_operator     = exclusion.value.selector_match_operator
          selector                    = exclusion.value.selector
        }
      }
      dynamic "managed_rule_set" {
        for_each = managed_rules.value.managed_rule_Set
        content {
          type        = managed_rule_set.value.type
          version = managed_rule_set.value.version

          dynamic "rule_group_override" {
            for_each = managed_rule_set.value.rule_group_override
            content {
              rule_group_name = rule_group_override.value.rule_group_name
              disabled_rules  = rule_group_override.value.disabled_rules
            }
          }
        }
      }
    }
  }
}





