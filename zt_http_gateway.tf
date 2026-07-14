#creates sample do not inspect policy
resource "cloudflare_zero_trust_gateway_policy" "http_do_not_inspect_policy" {
  account_id  = var.cloudflare_account_id
  action      = "off"
  name        = "Do Not Inspect"
  description = "Sample policy to bypass TLS inspection for specific traffic (e.g. trusted applications or domains)"
  enabled     = true
  filters     = ["http"]
  precedence  = 1001
  traffic     = "any(app.ids[*] in {661 710}) or any(http.conn.domains[*] in {\"cloudflare.net\"})"
}

# Allow and log MCP protocol traffic with payload logging
resource "cloudflare_zero_trust_gateway_policy" "http_allow_and_log_mcp" {
  account_id  = var.cloudflare_account_id
  action      = "allow"
  name        = "Allow and Log MCP Traffic"
  description = "Allow MCP protocol traffic but log payloads for monitoring and analysis"
  enabled     = true
  filters     = ["http"]
  precedence  = 1051

  traffic = format("any(dlp.profiles[*] in {\"%s\"})", cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id)

  rule_settings = {
    payload_log = {
      enabled = true
    }
    notification_settings = {
      enabled = false
    }
  }
}

# Block secrets and API keys from being exfiltrated via HTTP
resource "cloudflare_zero_trust_gateway_policy" "http_block_dlp_keys_tokens" {
  account_id  = var.cloudflare_account_id
  action      = "block"
  name        = "Block DLP Keys and Tokens"
  description = "Block HTTP traffic containing secrets or API keys matched by the Keys/Tokens DLP profile"
  enabled     = true
  filters     = ["http"]
  precedence  = 1052

  traffic = format("any(dlp.profiles[*] in {\"%s\"})", cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id)

  rule_settings = {
    block_page_enabled = false
  }
}

# Block all AI providers except OpenAI (ChatGPT) — disabled by default
# Enable this rule and the redirect rule below to funnel users to the approved AI tool
resource "cloudflare_zero_trust_gateway_policy" "http_block_ai_providers" {
  account_id  = var.cloudflare_account_id
  action      = "block"
  name        = "Block AI Providers"
  description = "Block all AI applications except OpenAI/ChatGPT (app type 25 = Artificial Intelligence category)"
  enabled     = false
  filters     = ["http"]
  precedence  = 1053

  # app.type.ids {25} = Artificial Intelligence category; exclude ChatGPT (1199) and ChatGPT Do Not Inspect (1862)
  traffic = "any(app.type.ids[*] in {25}) and not(any(app.ids[*] in {1199 1862}))"

  rule_settings = {
    block_page_enabled = false
  }
}

# Redirect any remaining AI traffic to ChatGPT — disabled by default
# Enable together with the block rule above to canonicalise AI usage to a single approved tool
resource "cloudflare_zero_trust_gateway_policy" "http_redirect_to_chatgpt" {
  account_id  = var.cloudflare_account_id
  action      = "redirect"
  name        = "Redirect to ChatGPT"
  description = "Redirect all sanctioned AI application traffic to ChatGPT"
  enabled     = false
  filters     = ["http"]
  precedence  = 1054

  traffic = "any(app.type.ids[*] in {25}) and not(any(app.ids[*] in {1199 1862}))"

  rule_settings = {
    redirect = {
      target_uri              = "https://chatgpt.com"
      preserve_path_and_query = false
      include_context         = false
    }
  }
}

#creates sample http policy to detect AI prompts
resource "cloudflare_zero_trust_gateway_policy" "http_allow_and_log_genai_prompt" {
  account_id  = var.cloudflare_account_id
  action      = "allow"
  name        = "Allow and Log GenAI Prompts"
  description = "Allow traffic but log potential GenAI prompts for monitoring and analysis"
  enabled     = false
  filters     = ["http"]
  precedence  = 1050
  traffic     = "(any(app.ids[*] == 1199) and any(app_control.controls[*] in {1652})) or (any(app.ids[*] == 1937) and any(app_control.controls[*] in {2598})) or (any(app.ids[*] == 2430) and any(app_control.controls[*] in {2127})) or (any(app.ids[*] == 1340) and any(app_control.controls[*] in {1657}))"
  rule_settings = {
    gen_ai_prompt_log = {
      enabled = true
    },
    notification_settings = {
      enabled = false
    },
    forensic_copy = {
      enabled = false
    }
  }
}

resource "cloudflare_zero_trust_gateway_policy" "HTTP_allowed_corporate_domains_list" {
  account_id  = var.cloudflare_account_id
  action      = "allow"
  name        = "Allow Domains List"
  description = "Allow traffic to specific corporate and service domains, based on a Zero Trust List"
  enabled     = false
  filters     = ["http"]
  precedence  = 1152
  traffic     = format("any(http.request.domains[*] in $%s)", cloudflare_zero_trust_list.allowed_domains_list.id)

}

#creates sample http policy to block all Cloudflare security categories
resource "cloudflare_zero_trust_gateway_policy" "http_all_security_categories" {
  account_id  = var.cloudflare_account_id
  action      = "block"
  name        = "All Security Categories"
  description = "Block all security categories for http traffic"
  enabled     = true
  filters     = ["http"]
  precedence  = 1101

  traffic = "any(http.request.uri.security_category[*] in {${join(" ", [
    local.subcategories_map["Anonymizer"],
    local.subcategories_map["Command and Control & Botnet"],
    local.subcategories_map["Compromised Domain"],
    local.subcategories_map["Cryptomining"],
    local.subcategories_map["Malware"],
    local.subcategories_map["Phishing"],
    local.subcategories_map["Potentially unwanted software"],
    local.subcategories_map["Private IP Address"],
    local.subcategories_map["Spam"],
    local.subcategories_map["Spyware"],
    local.subcategories_map["DNS Tunneling"],
    local.subcategories_map["DGA Domains"],
    local.subcategories_map["Brand Embedding"],
    local.subcategories_map["Scam"],
    local.subcategories_map["Unreachable"],
    local.subcategories_map["URL Alias/Redirect"],
    local.subcategories_map["No Content"],
    local.subcategories_map["Miscellaneous"],
    local.subcategories_map["Login Screens"],
    local.subcategories_map["New Domains"],
    local.subcategories_map["Parked & For Sale Domains"],
    local.subcategories_map["Newly Seen Domains"],
  ])}})"

  rule_settings = {
    block_page_enabled    = true,
    notification_settings = { enabled = true, msg = "High Risk Webpage Blocked" },
  }
}

resource "cloudflare_zero_trust_gateway_policy" "http_content_filtering" {
  account_id  = var.cloudflare_account_id
  name        = "HTTP Content Filtering"
  description = "Block specific content categories"
  enabled     = true
  action      = "block"
  filters     = ["http"]
  precedence  = 1201

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "any(http.request.uri.security_category[*] in {${join(" ", [
    local.subcategories_map["Advertisements"],
    local.subcategories_map["Cryptocurrency"],
    local.subcategories_map["Gambling"],
    local.subcategories_map["P2P"],
    local.subcategories_map["Drugs"],
    local.subcategories_map["Hacking"],
    local.subcategories_map["Profanity"],
    local.subcategories_map["Questionable Activities"],
    local.subcategories_map["Militancy, Hate & Extremism"],
    local.subcategories_map["Violence"],
    local.subcategories_map["Weapons"],
    local.subcategories_map["Unreliable Information"],
  ])}})"

}

resource "cloudflare_zero_trust_gateway_policy" "http_restricted_countries" {
  account_id  = var.cloudflare_account_id
  name        = "Restricted Countries"
  description = "Block traffic from restricted countries"
  enabled     = true
  action      = "block"
  precedence  = 1301
  filters     = ["http"]
  rule_settings = {
    block_page_enabled = false
  }
  traffic = "http.dst_ip.geo.country in {\"AF\" \"AO\" \"BY\" \"CN\" \"CD\" \"CU\" \"CY\" \"HT\" \"IR\" \"IQ\" \"KP\" \"LR\" \"LY\" \"NG\" \"RU\" \"RW\" \"SO\" \"SD\" \"SY\" \"UA\" \"VN\" \"YE\" \"ZW\" \"LK\"}"

}

resource "cloudflare_zero_trust_gateway_policy" "http_restricted_extensions" {
  account_id  = var.cloudflare_account_id
  name        = "Restricted Extensions"
  description = "Block traffic from restricted extensions"
  enabled     = true
  action      = "block"
  precedence  = 1401
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "http.request.uri.path ~ \"[.](hta|doc|reg|zip|xls|Ink|iso|dll|chm)\""

}

resource "cloudflare_zero_trust_gateway_policy" "http_block_beacons" {
  account_id  = var.cloudflare_account_id
  name        = "Block Beacons"
  description = "Block beacon traffic"
  enabled     = true
  action      = "block"
  precedence  = 1501
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "http.request.host ~ \".*beacon.*\""

}

resource "cloudflare_zero_trust_gateway_policy" "http_block_executables" {
  account_id  = var.cloudflare_account_id
  name        = "Block Executables"
  description = "Block executable file types"
  enabled     = true
  action      = "block"
  precedence  = 1601
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "http.request.uri.path ~ \"[.](exe|bat|cmd|sh|pl|py)\""

}

resource "cloudflare_zero_trust_gateway_policy" "http_block_executables_by_mimetypes" {
  account_id  = var.cloudflare_account_id
  name        = "Block Executables by MIME Type"
  description = "Block executable file types by MIME type"
  enabled     = true
  action      = "block"
  precedence  = 1701
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "http.download.mime == \"application/x-msdos-program\" or http.download.mime == \"application/octet-stream\""

}

resource "cloudflare_zero_trust_gateway_policy" "http_block_torrents" {
  account_id  = var.cloudflare_account_id
  name        = "Block Torrents"
  description = "Block torrent file downloads"
  enabled     = true
  action      = "block"
  precedence  = 1801
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "http.request.uri.path ~ \"[.](torrent)\""

}

resource "cloudflare_zero_trust_gateway_policy" "http_isolate_newly_seen" {
  account_id  = var.cloudflare_account_id
  name        = "Isolate Newly Seen Domains"
  description = "Isolate devices that are newly seen domains and other dodgy categories"
  enabled     = true
  action      = "isolate"
  precedence  = 1901
  filters     = ["http"]

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "any(http.request.uri.content_category[*] in {${join(" ", [
    local.subcategories_map["Deceptive Ads"],
    local.subcategories_map["Drugs"],
    local.subcategories_map["Hacking"],
    local.subcategories_map["Profanity"],
    local.subcategories_map["Questionable Activities"],
    local.subcategories_map["Militancy, Hate & Extremism"],
    local.subcategories_map["Unreliable Information"],
    local.subcategories_map["Parked & For Sale Domains"],
    local.subcategories_map["New Domains"],
    local.subcategories_map["Newly Seen Domains"],
    local.subcategories_map["Login Screens"],
    local.subcategories_map["No Content"],
    local.subcategories_map["Unreachable"],
    local.subcategories_map["Gambling"],
  ])}})"
}