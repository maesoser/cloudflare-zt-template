# Force Safe Search on major search engines and YouTube
resource "cloudflare_zero_trust_gateway_policy" "dns_safe_search" {
  account_id  = var.cloudflare_account_id
  name        = "Safe Search"
  description = "Force Safe Search on Google, Bing, YouTube and DuckDuckGo"
  precedence  = 900
  enabled     = true
  filters     = ["dns"]
  action      = "safesearch"
  traffic     = "any(dns.domains[*] in {\"google.com\" \"bing.com\" \"youtube.com\" \"duckduckgo.com\"})"
}

resource "cloudflare_zero_trust_gateway_policy" "force_ipv4" {
  account_id  = var.cloudflare_account_id
  name        = "Force IPv4"
  description = "Block AAAA (IPv6) DNS queries to force IPv4 resolution"
  precedence  = 1000
  enabled     = false
  filters     = ["dns"]
  rule_settings = {
    block_page_enabled = false
  }

  traffic = "dns.query_rtype == \"AAAA\""
  action  = "block"
}


resource "cloudflare_zero_trust_gateway_policy" "security_threats" {
  account_id  = var.cloudflare_account_id
  name        = "Security Threats"
  description = "Block all Security Risks categories"
  precedence  = 1100
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "any(dns.content_category[*] in {${join(" ", [
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

  action = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "content_filtering" {
  account_id  = var.cloudflare_account_id
  name        = "Content Filtering"
  description = "Block specific content categories"
  precedence  = 1200
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "any(dns.content_category[*] in {${join(" ", [
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

  action = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "ofac_geo_blocking" {
  account_id  = var.cloudflare_account_id
  name        = "OFAC Geo-Blocking"
  description = "Block DNS queries resolving to sanctioned countries"
  precedence  = 1300
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "any(dns.dst.geo.country[*] in {\"AF\" \"BY\" \"CD\" \"CU\" \"IR\" \"IQ\" \"KP\" \"MM\" \"RU\" \"SD\" \"SY\" \"UA\" \"ZW\"})"
  action  = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "tld_block_countries" {
  account_id  = var.cloudflare_account_id
  name        = "TLD Country Block - CN and RU"
  description = "Block Chinese and Russian top-level domains"
  precedence  = 1400
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "dns.fqdn ~ \"[.](cn|ru)$\""
  action  = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "tld_block_phishing" {
  account_id  = var.cloudflare_account_id
  name        = "TLD Phishing Block - Phishing TLDs"
  description = "Block commonly abused TLDs for phishing"
  precedence  = 1500
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "dns.fqdn ~ \"[.](rest|hair|top|cfd|boats|beauty|mom|skin|okinawa|zip|mobi)$\""
  action  = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "autodiscover_block" {
  account_id  = var.cloudflare_account_id
  name        = "Autodiscover Block"
  description = "Block autodiscover DNS queries"
  precedence  = 1600
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = "dns.fqdn ~ \"autodiscover.*\""
  action  = "block"
}

resource "cloudflare_zero_trust_gateway_policy" "block_apple_tracking" {
  account_id  = var.cloudflare_account_id
  name        = "Block Common Tracking Domains"
  description = "Block Common tracking domains"
  precedence  = 1700
  filters     = ["dns"]
  enabled     = true

  rule_settings = {
    block_page_enabled = false
  }

  traffic = format("any(dns.domains[*] in $%s)", cloudflare_zero_trust_list.tracking_domains_list.id)
  action  = "block"
}