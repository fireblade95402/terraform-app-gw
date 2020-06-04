variable "resource_group_name" {
  description = "(Required) Resource Group of the App GW to be created"  
}

variable "location" {
  description = "(Required) Location of the App GW to be created"  
}

variable "app-gw-object" {
  description = "(Required) Front Door Object configuration"  
}

variable "tags" {
  description = "(Required) Tags of the App GW to be created"  
}

