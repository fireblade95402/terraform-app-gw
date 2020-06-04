variable "app-gw-rg" {
  description = "(Required) Resource Group of the App GW WAF Policy to be created"  
}

variable "location" {
  description = "(Required) Location of the App GW WAF Policy to be created"
}

variable "app-gw-waf-object" {
  description = "(Required) AFD Settings of the App GW WAF Policy/s to be created"  
}

variable "tags" {
  description = "(Required) Tags of the App GW WAF Policy to be created"  
}
