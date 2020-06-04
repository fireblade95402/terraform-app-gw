#Create 1 to x Azure Front Door Policies
module "azure_app_gw_waf" {
  source = "./app-gw-waf"

  front-door-rg           = var.front-door-rg
  front-door-waf-object   = var.front-door-waf-object
  tags                    = var.tags

}
  
#Create Azure Front Door Resource
resource "azurerm_application_gateway" "appgw" {
  depends_on                                   = [module.azurerm_web_application_firewall_policy]
  name                                         = var.app-gw-object.name
  location                                     = var.location
  resource_group_name                          = var.front-door-rg
  tags                                         = local.tags
  zones                                        = var.app-gw-object.zones
  enable_http2                                 = var.app-gw-object.enable_http2 
  firewall_policy_id = var.app-gw-object.web_application_firewall_policy_link_name != "" ? module.azurerm_web_application_firewall_policy.waf-map[var.app-gw-object.web_application_firewall_policy_link_name] : ""          

dynamic "sku" {
      for_each = var.app-gw-object.sku
      content {
        name          = sku.value.name
        tier          = sku.value.tier
        capacity      = sku.value.capacity
      }
    }

dynamic " backend_address_pool" {
      for_each = var.app-gw-object. backend_address_pool
      content {
        name          =  backend_address_pool.value.name
        fqdns         =  backend_address_pool.value.fqdns
        ip_addresses  =  backend_address_pool.value.ip_addresses
      }
    }
  
  
  dynamic "backend_http_settings" {
      for_each = var.app-gw-object.backend_http_settings
      content {
        cookie_based_affinity                 = backend_http_settings.cookie_based_affinity
        affinity_cookie_name                  = backend_http_settings.affinity_cookie_name
        name                                  = backend_http_settings.name
        path                                  = backend_http_settings.path
        port                                  = backend_http_settings.port
        probe_name                            = backend_http_settings.probe_name
        protocol                              = backend_http_settings.protocol
        request_timeout                       = backend_http_settings.request_timeout
        host_name                             = backend_http_settings.host_name
        pick_host_name_from_backend_address   = backend_http_settings.pick_host_name_from_backend_address
        authentication_certificate            = backend_http_settings.authentication_certificate
        trusted_root_certificate_names        = backend_http_settings.trusted_root_certificate_names
        connection_draining                   = backend_http_settings.connection_draining
      }
    }

dynamic "frontend_ip_configuration" {
      for_each = var.app-gw-object.frontend_ip_configuration
      content {
        name                          = frontend_ip_configuration.value.name
        subnet_id                     = frontend_ip_configuration.value.subnet_id
        private_ip_address            = frontend_ip_configuration.value.private_ip_address
        public_ip_address_id          = frontend_ip_configuration.value.public_ip_address_id
        private_ip_address_allocation = frontend_ip_configuration.value.private_ip_address_allocation
      }
    }

dynamic "frontend_port" {
      for_each = var.app-gw-object.frontend_port
      content {
        name          = frontend_port.value.name
        port          = frontend_port.value.port
      }
    }

dynamic "gateway_ip_configuration" {
      for_each = var.app-gw-object.gateway_ip_configuration
      content {
        name          = gateway_ip_configuration.value.name
        subnet_id     = gateway_ip_configuration.value.subnet_id
      }
    }

dynamic "http_listener" {
      for_each = var.app-gw-object.http_listener
      content {
        name                      = http_listener.value.name
        frontend_port_name        = http_listener.value.name
        host_name                 = http_listener.value.name
        host_names                = http_listener.value.name
        protocol                  = http_listener.value.name
        require_sni               = http_listener.value.name
        ssl_certificate_name      = http_listener.value.name
        
        dynamic "custom_error_configuration" {
          for_each = http_listener.value.custom_error_configuration
          content {
            status_code           = custom_error_configuration.value.status_code 
            custom_error_page_url = custom_error_configuration.value.custom_error_page_url
          }
        }
      }
    }

dynamic "identity" {
      for_each = var.app-gw-object.identity
      content {
        type          = identity.value.type
        identity_ids  = identity.value.identity_ids
      }
    }


dynamic "request_routing_rule" {
      for_each = var.app-gw-object.request_routing_rule
      content {
        name                        = request_routing_rule.value.name
        rule_type                   = request_routing_rule.value.rule_type
        http_listener_name          = request_routing_rule.value.http_listener_name
        backend_address_pool_name   = request_routing_rule.value.backend_address_pool_name
        backend_http_settings_name  = request_routing_rule.value.backend_http_settings_name
        redirect_configuration_name = request_routing_rule.value.redirect_configuration_name
        rewrite_rule_set_name       = request_routing_rule.value.rewrite_rule_set_name
        url_path_map_name           = request_routing_rule.value.url_path_map_name
      }
    }

dynamic "authentication_certificate" {
      for_each = var.app-gw-object.authentication_certificate
      content {
        name          = authentication_certificate.value.name
        data         = authentication_certificate.value.data
      }
    }

dynamic "trusted_root_certificate" {
      for_each = var.app-gw-object.trusted_root_certificate
      content {
        name          = trusted_root_certificate.value.name
        data         = trusted_root_certificate.value.data
      }
    }

dynamic "ssl_policy" {
      for_each = var.app-gw-object.ssl_policy
      content {
        disabled_protocols          = ssl_policy.value.disabled_protocols
        policy_type                 = ssl_policy.value.type        
        policy_name                 = ssl_policy.value.policy_name
        cipher_suites               = ssl_policy.value.cipher_suites
        min_protocol_version        = ssl_policy.value.min_protocol_version 
      }
    }

dynamic "probe" {
      for_each = var.app-gw-object.todo
      content {
        host                                        = probe.value.host
        interval                                    = probe.value.interval
        name                                        = probe.value.name
        protocol                                    = probe.value.protocol
        path                                        = probe.value.path
        timeout                                     = probe.value.timeout
        unhealthy_threshold                         = probe.value.unhealthy_threshold
        pick_host_name_from_backend_http_settings   = probe.value.pick_host_name_from_backend_http_settings
        match                                       = probe.value.match
        minimum_servers                             = probe.value.minimum_servers
      }
    }
  

dynamic "ssl_certificate" {
      for_each = var.app-gw-object.ssl_certificate
      content {
        name                = ssl_certificate.value.name
        data                = ssl_certificate.value.data
        password            = ssl_certificate.value.password
        key_vault_secret_id = ssl_certificate.value.key_vault_secret_id        
      }
    }
  

  dynamic "url_path_map" {
      for_each = var.app-gw-object.url_path_map
      content {
        name                                = url_path_map.value.name
        default_backend_address_pool_name   = url_path_map.value.default_backend_address_pool_name
        default_backend_http_settings_name  = url_path_map.value.default_backend_http_settings_name
        default_redirect_configuration_name = url_path_map.value.default_redirect_configuration_name
        default_rewrite_rule_set_name       = url_path_map.value.default_rewrite_rule_set_name
        
        dynamic "path_rule" {
          for_each = url_path_map.value.path_rule
          content {
            id                        = path_rule.value.id
            backend_address_pool_id   = path_rule.value.backend_address_pool_id
            backend_http_settings_id  = path_rule.value.backend_http_settings_id
            redirect_configuration_id = path_rule.value.redirect_configuration_id
            rewrite_rule_set_id       = path_rule.value.rewrite_rule_set_id
          }
        }
      }
    }
  

  dynamic "waf_configuration" {
      for_each = var.app-gw-object.waf_configuration
      content {
        enabled = waf_configuration.value.
        firewall_mode = waf_configuration.value.
        rule_set_type = waf_configuration.value.
        rule_set_version = waf_configuration.value.
        
        dynamic "disabled_rule_group" {
          for_each = waf_configuration.value.disabled_rule_group
          content {
            rule_group_name = disabled_rule_group.value.rule_group_name
            rules           = disabled_rule_group.value.rules
          }
        }
       
        file_upload_limit_mb = waf_configuration.value.
        request_body_check = waf_configuration.value.
        max_request_body_size_kb = waf_configuration.value.
        
        dynamic "exclusion" {
          for_each = waf_configuration.value.exclusion
          content {
            match_variable          = exclusion.value.match_variable
            selector_match_operator = exclusion.value.selector_match_operator
            selector                = exclusion.value.selector
          }
        }
      }
    }
  


  dynamic "custom_error_configuration" {
      for_each = var.app-gw-object.custom_error_configuration
      content {
        status_code           = custom_error_configuration.value.status_code
        custom_error_page_url = custom_error_configuration.value.custom_error_page_url
      }
    }
  


  dynamic "redirect_configuration" {
      for_each = var.app-gw-object.redirect_configuration
      content {
        name                  = redirect_configuration.value.name
        redirect_type         = redirect_configuration.value.redirect_type
        target_listener_name  = redirect_configuration.value.target_listener_name 
        target_url            = redirect_configuration.value.target_url 
        include_path          = redirect_configuration.value.include_path 
        include_query_string  = redirect_configuration.value.include_query_string 
      }
    }
  

  dynamic "autoscale_configuration" {
      for_each = var.app-gw-object.autoscale_configuration
      content {
        min_capacity          = autoscale_configuration.value.min_capacity
        max_capacity          = autoscale_configuration.value.max_capacity
      }
    }
  
    dynamic "rewrite_rule_set" {
      for_each = var.app-gw-object.rewrite_rule_set
      content {
        name          = rewrite_rule_set.value.name
        dynamic "rewrite_rule" {
          for_each = rewrite_rule_set.value.rewrite_rule
          content {
            name          = rewrite_rule.value.name
            rule_sequence = rewrite_rule.value.rule_sequence

            dynamic "condition" {
              for_each = rewrite_rule.value.condition
              content {
                variable    = condition.value.variable
                pattern     =  condition.value.pattern
                ignore_case = condition.value.ignore_case
                negate      = condition.value.negate
              }
            }
            dynamic " request_header_configuration" {
              for_each = rewrite_rule.value.request_header_configuration
              content {
                header_name   = request_header_configuration.value.header_name
                header_value  = request_header_configuration.value.header_value
              }
            }
            dynamic "response_header_configuration" {
              for_each = rewrite_rule.value.response_header_configuration
              content {
                header_name   = response_header_configuration.value.header_name
                header_value  = response_header_configuration.value.header_value
              }
            }
          }
        }
      }
    }
}
