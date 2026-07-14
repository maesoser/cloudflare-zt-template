# ── MCP Detection Profile ─────────────────────────────────────────────────────

resource "cloudflare_zero_trust_dlp_custom_profile" "mcp_detect_custom" {
  account_id          = var.cloudflare_account_id
  name                = "MCP Detection"
  description         = "Detect MCP protocol traffic"
  allowed_match_count = 0
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_initialize_method" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Initialize Method"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"initialize\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_tools_call" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Tools Call"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"tools/call\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_tools_list" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Tools List"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"tools/list\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_resources_read" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Resources Read"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"resources/read\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_resources_list" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Resources List"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"resources/list\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_prompts_list" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Prompts List"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"prompts/(list|get)\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_sampling_create_message" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Sampling Create Message"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"sampling/createMessage\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_protocol_version" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Protocol Version"
  enabled    = true
  pattern = {
    regex = "\"protocolVersion\"\\s{0,5}:\\s{0,5}\"202[4-9]"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_notifications_initialized" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Notifications Initialized"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"notifications/initialized\""
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mcp_roots_list" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.mcp_detect_custom.id
  name       = "MCP Roots List"
  enabled    = true
  pattern = {
    regex = "\"method\"\\s{0,5}:\\s{0,5}\"roots/list\""
  }
}

# ── Keys / Tokens Profile ─────────────────────────────────────────────────────
resource "cloudflare_zero_trust_dlp_custom_profile" "keys_tokens_custom" {
  account_id          = var.cloudflare_account_id
  name                = "Regex Keys/Tokens"
  description         = "List of regex queries for common Enterprise keys and tokens"
  allowed_match_count = 0
}

moved {
  from = cloudflare_zero_trust_dlp_profile.keys_tokens_custom
  to   = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom
}

resource "cloudflare_zero_trust_dlp_custom_entry" "aws_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "AWS API Key"
  enabled    = true
  pattern = {
    regex = "AKIA[0-9A-Z]{16}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "aws_appsync_graphql_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "AWS AppSync GraphQL Key"
  enabled    = true
  pattern = {
    regex = "da2-[a-z0-9]{26}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "amazon_mws_auth_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Amazon MWS Auth Token"
  enabled    = true
  pattern = {
    regex = "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "facebook_access_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Facebook Access Token"
  enabled    = true
  pattern = {
    regex = "EAACEdEose0cBA[0-9A-Za-z]"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "google_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Google API Key"
  enabled    = true
  pattern = {
    regex = "AIza[0-9A-Za-z\\-_]{35}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "google_cloud_platform_oauth" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Google Cloud Platform OAuth"
  enabled    = true
  pattern = {
    regex = "[0-9]-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "google_oauth_access_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Google OAuth Access Token"
  enabled    = true
  pattern = {
    regex = "ya29\\.[0-9A-Za-z\\-_]"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "heroku_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Heroku API Key"
  enabled    = true
  pattern = {
    regex = "[hH][eE][rR][oO][kK][uU].[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mailchimp_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "MailChimp API Key"
  enabled    = true
  pattern = {
    regex = "[0-9a-f]{32}-us[0-9]{1,2}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "mailgun_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Mailgun API Key"
  enabled    = true
  pattern = {
    regex = "key-[0-9a-zA-Z]{32}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "pgp_private_key_block" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "PGP private key block"
  enabled    = true
  pattern = {
    regex = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "paypal_braintree_access_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "PayPal Braintree Access Token"
  enabled    = true
  pattern = {
    regex = "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "picatic_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Picatic API Key"
  enabled    = true
  pattern = {
    regex = "sk_live_[0-9a-z]{32}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "rsa_private_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "RSA private key"
  enabled    = true
  pattern = {
    regex = "-----BEGIN RSA PRIVATE KEY-----"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "ssh_dsa_private_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "SSH (DSA) private key"
  enabled    = true
  pattern = {
    regex = "-----BEGIN DSA PRIVATE KEY-----"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "ssh_ec_private_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "SSH (EC) private key"
  enabled    = true
  pattern = {
    regex = "-----BEGIN EC PRIVATE KEY-----"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "slack_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Slack Token"
  enabled    = true
  pattern = {
    regex = "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "slack_webhook" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Slack Webhook"
  enabled    = true
  pattern = {
    regex = "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "square_access_token" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Square Access Token"
  enabled    = true
  pattern = {
    regex = "sq0atp-[0-9A-Za-z\\-_]{22}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "square_oauth_secret" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Square OAuth Secret"
  enabled    = true
  pattern = {
    regex = "sq0csp-[0-9A-Za-z\\-_]{43}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "stripe_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Stripe API Key"
  enabled    = true
  pattern = {
    regex = "sk_live_[0-9a-zA-Z]{24}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "stripe_restricted_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Stripe Restricted API Key"
  enabled    = true
  pattern = {
    regex = "rk_live_[0-9a-zA-Z]{24}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "telegram_bot_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Telegram Bot API Key"
  enabled    = true
  pattern = {
    regex = "[0-9]:AA[0-9A-Za-z\\-_]{33}"
  }
}

resource "cloudflare_zero_trust_dlp_custom_entry" "twilio_api_key" {
  account_id = var.cloudflare_account_id
  profile_id = cloudflare_zero_trust_dlp_custom_profile.keys_tokens_custom.id
  name       = "Twilio API Key"
  enabled    = true
  pattern = {
    regex = "SK[0-9a-fA-F]{32}"
  }
}
