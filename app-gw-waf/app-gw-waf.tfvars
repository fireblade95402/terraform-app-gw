app-gw-rg = "temp"
location = "uksouth"
tags = {test = "test"}
app-gw-waf-object = {
  waf1 = {
    name         = "appgw-test-policy"
    custom_rules = {
      cr1 = {
        name      = "Rule1"
        priority  = 1
        rule_type = "MatchRule"
        action    = "Block"

        match_conditions = {
          mc1 = {
            match_variables     = {
              mv1 = {
                variable_name = "RemoteAddr"
                selector = ""
              }
            }
            match_values       = ["192.168.1.0/24", "10.0.0.0/24"]
            operator           = "IPMatch"
            negation_condition = false
          }
        }
      },
      cr2 = {
        name      = "Rule2"
        priority  = 2
        rule_type = "MatchRule"
        action    = "Block"

        match_conditions = {
          mc1 = {
            match_variables     = {
              mv1 = {
                variable_name = "RemoteAddr"
                selector = ""
              }
            }
            match_values       = ["192.168.1.0/24"]
            operator           = "IPMatch"
            negation_condition = false
          },
          mc2 = {
            match_variables     = {
              mv1 = {
                variable_name = "RequestHeaders"
                selector = "UserAgent"
              }
            }
            match_values       = ["Windows"]
            operator           = "Contains"
            negation_condition = false
          }
        }
      }
    }

    policy_settings =  {
      enabled = true
      mode = "Prevention"
    }

    managed_rules = {
      mr1 = {
        exclusion = {
          ex1 = {
            match_variable = "RequestHeaderNames"
            selector_match_operator       = "Equals"
            selector       = "x-company-secret-header"
          },
          ex2 = {
            match_variable = "RequestCookieNames"
            selector_match_operator       = "EndsWith"
            selector       = "too-tasty"
          }
        }
        managed_rule_Set = {
          or1 = {
            type = "OWASP"
            version = "3.0"
            rule_group_override = {
              ro1 = {
                rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
                disabled_rules = ["920300","920440"]
              }
            }
            }

        }
      }
    }
  }


}
  
