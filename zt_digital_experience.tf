# ── DEX Rules ────────────────────────────────────────────────────────────────

resource "cloudflare_zero_trust_dex_rule" "desktop_devices" {
  account_id  = var.cloudflare_account_id
  name        = "Desktop devices"
  description = "Targets Windows, macOS, Linux and ChromeOS devices"
  match       = "os.name in {\"windows\" \"mac\" \"linux\" \"chromeos\"}"
}

resource "cloudflare_zero_trust_dex_rule" "mobile_devices" {
  account_id  = var.cloudflare_account_id
  name        = "Mobile Devices"
  description = "Targets Android and iOS devices"
  match       = "os.name in {\"android\" \"ios\"}"
}

# ── DEX Tests ─────────────────────────────────────────────────────────────────
resource "cloudflare_zero_trust_dex_test" "cloudflare_status_http" {
  account_id  = var.cloudflare_account_id
  name        = "Cloudflare Status Page"
  description = "60 min HTTP Get for cloudflarestatus.com"
  interval    = "0h30m0s"
  enabled     = true
  data = {
    host   = "http://cloudflarestatus.com/"
    kind   = "http"
    method = "GET"
  }
}

resource "cloudflare_zero_trust_dex_test" "vodafone_http" {
  account_id  = var.cloudflare_account_id
  name        = "Vodafone"
  description = "60 min HTTP Get for vodafone.com"
  interval    = "1h0m0s"
  enabled     = true
  data = {
    host   = "https://www.vodafone.com/"
    kind   = "http"
    method = "GET"
  }
}

resource "cloudflare_zero_trust_dex_test" "github_http" {
  account_id  = var.cloudflare_account_id
  name        = "Github"
  description = "60 min HTTP Get for github.com"
  interval    = "1h0m0s"
  enabled     = true
  data = {
    host   = "https://github.com/"
    kind   = "http"
    method = "GET"
  }
}

resource "cloudflare_zero_trust_dex_test" "google_mail_http" {
  account_id  = var.cloudflare_account_id
  name        = "Google Mail"
  description = "60 min HTTP Get for mail.google.com"
  interval    = "1h00m0s"
  enabled     = true
  data = {
    host   = "https://mail.google.com/"
    kind   = "http"
    method = "GET"
  }
}

resource "cloudflare_zero_trust_dex_test" "salesforce_traceroute" {
  account_id  = var.cloudflare_account_id
  name        = "Salesforce"
  description = "24 hr Traceroute for salesforce.com"
  interval    = "24h0m0s"
  enabled     = true
  data = {
    host = "salesforce.com"
    kind = "traceroute"
  }
}

resource "cloudflare_zero_trust_dex_test" "google_meet_http" {
  account_id  = var.cloudflare_account_id
  name        = "Google Meet"
  description = "60 min HTTP Get for meet.google.com"
  interval    = "1h00m0s"
  enabled     = true
  data = {
    host   = "https://meet.google.com/"
    kind   = "http"
    method = "GET"
  }
}

resource "cloudflare_zero_trust_dex_test" "teams_traceroute" {
  account_id  = var.cloudflare_account_id
  name        = "Microsoft Teams"
  description = "24 hr Traceroute for Microsoft Teams"
  interval    = "24h0m0s"
  enabled     = true
  data = {
    host = "teams.microsoft.com"
    kind = "traceroute"
  }
}