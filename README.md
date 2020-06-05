# Create Applciation Gateway plus WAF Policy with Terraform Modules

tfvars files have the documentation of the parameters. 

This file is * tbc *

Here's a rough process to get this up and running:

* Setup the tfvars file for the waf policy and run the deployment. This creates the WAF policy
* Get the WAF Policy ID and update the app gateway's tfvars file (firewall_policy_id) with the WAF Policy ID
* You'll also need to create a Public IP with Standard sku and get the ID to polulate the Public IP in frontend_ip_configuration
* You'll need to update the subnet id in the gateway_ip_configuration section
* Then deploy the app-gw 