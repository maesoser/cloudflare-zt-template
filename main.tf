terraform {
  required_version = ">= 1.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.22.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for Domain configuration"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare Account ID for Zero Trust configuration"
  type        = string
  sensitive   = true
}

variable "cloudflare_api_token" {
  description = "Cloudflare API Token with Zero Trust permissions"
  type        = string
  sensitive   = true
}

# Retrieve the Zero Trust category list
data "cloudflare_zero_trust_gateway_categories_list" "categories" {
  account_id = var.cloudflare_account_id
}

# Retrieve the Zero Trust app list
data "cloudflare_zero_trust_gateway_app_types_list" "apps" {
  account_id = var.cloudflare_account_id
}

locals {
  _main_categories_map_grouped = {
    for idx, c in data.cloudflare_zero_trust_gateway_categories_list.categories.result :
    c.name => c.id...
  }
  main_categories_map = {
    for name, ids in local._main_categories_map_grouped : name => ids[0]
  }

  # Flatten all subcategories across all categories into a single list of {name, id} objects,
  # then group by name to handle duplicates, taking the first id.
  _all_subcategories = flatten([
    for c in data.cloudflare_zero_trust_gateway_categories_list.categories.result : [
      for v in coalesce(c.subcategories, []) : { name = v.name, id = v.id }
    ]
  ])
  _subcategories_map_grouped = {
    for item in local._all_subcategories : item.name => item.id...
  }
  subcategories_map = {
    for name, ids in local._subcategories_map_grouped : name => ids[0]
  }

  # Use ... to group duplicate names into a list, then take the first id.
  # The Cloudflare API occasionally returns duplicate app names (e.g. "Playeur").
  _main_apps_map_grouped = {
    for idx, c in data.cloudflare_zero_trust_gateway_app_types_list.apps.result :
    c.name => c.id...
  }
  main_apps_map = {
    for name, ids in local._main_apps_map_grouped : name => ids[0]
  }
}

