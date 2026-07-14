

resource "cloudflare_zero_trust_list" "allowed_domains_list" {
  account_id  = var.cloudflare_account_id
  name        = "Allowed Domains"
  type        = "DOMAIN"
  description = "List of allowed corporate domains and necessary service domains"

  items = [
    { value = "edge-mqtt.facebook.com" },
    { value = "journey.pcms.apple.com" },
    { value = "apple-finance.query.yahoo.com" },
    { value = "api-glb-aeuw1b.smoot.apple.com" },
    { value = "region1.app-measurement.com" },
    { value = "eu1.bumble.com" },
    { value = "graph.facebook.com" },
    { value = "web.facebook.com" },
    { value = "tags.tiqcdn.com" },
  ]
}

resource "cloudflare_zero_trust_list" "isolated_domains_list" {
  account_id  = var.cloudflare_account_id
  name        = "Isolated Domains"
  type        = "DOMAIN"
  description = "List of domains that should be isolated"

  items = [
    { value = "cnn.com" },
    { value = "wikipedia.org" },
  ]
}

resource "cloudflare_zero_trust_list" "tracking_domains_list" {
  account_id  = var.cloudflare_account_id
  name        = "Common Tracking (Custom)"
  type        = "DOMAIN"
  description = "List of common tracking domains, based on the Apple Tracking Transparency framework and related services"
  items = [
    { value = "api-adservices.apple.com", description = "Apple tracking domain" },
    { value = "books-analytics-events.apple.com", description = "Apple analytics domain" },
    { value = "books-analytics-events.news.apple-dns.net", description = "Apple news analytics domain" },
    { value = "dzc-metrics.mzstatic.com", description = "Apple metrics domain" },
    { value = "feedbackws.icloud.com", description = "Apple feedback domain" },
    { value = "iadsdk.apple.com", description = "Apple iAd SDK domain" },
    { value = "metrics.apple.com", description = "Apple metrics domain" },
    { value = "metrics.icloud.com", description = "Apple metrics domain" },
    { value = "metrics.mzstatic.com", description = "Apple metrics domain" },
    { value = "notes-analytics-events.apple.com", description = "Apple notes analytics domain" },
    { value = "vortex-win.data.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "vortex.data.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "vortex.data.microsoft.com.akadns.net", description = "Microsoft telemetry domain" },
    { value = "vortex-sandbox.data.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "telemetry.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "telemetry.urs.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "choice.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "redir.metaservices.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "settings-sandbox.data.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "settings-win.data.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "telemetry.appex.bing.net", description = "Microsoft telemetry domain" },
    { value = "watson.live.com", description = "Microsoft telemetry domain" },
    { value = "watson.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "feedback.search.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "feedback.windows.com", description = "Microsoft telemetry domain" },
    { value = "corp.sts.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "diagnostics.support.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "i1.services.social.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "cache.datamart.windows.com", description = "Microsoft telemetry domain" },
    { value = "diagnostics.support.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "spynet2.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "spynetalt.microsoft.com", description = "Microsoft telemetry domain" },
    { value = "browser.events.data.microsoft.com", description = "Microsoft browser events domain" },
    { value = "onecollector.cloudapp.aria.akadns.net", description = "Office Telemetry" },
    { value = "prod.nexusrules.live.com.akadns.net", description = "Office Telemetry" },
    { value = "dit.whatsapp.net", description = "WhatsApp domain" },
    { value = "ssl.google-analytics.com", description = "Google Analytics domain" },
    { value = "app-measurement.com", description = "Google Analytics domain" },
    { value = "googleads.g.doubleclick.net", description = "Google Ads domain" },
    { value = "www.googleadservices.com", description = "Google Ads domain" },
    { value = "firebase-settings.crashlytics.com", description = "Firebase domain" },
    { value = "beacon.shazam.com", description = "Shazam beacon domain" },
    { value = "firebaselogging-pa.googleapis.com", description = "Firebase logging domain" },
    { value = "crashlyticsreports-pa.googleapis.com", description = "Crashlytics reports domain" },
    { value = "tracking.intl.miui.com", description = "MIUI tracking domain" },
    { value = "sdkconfig.ad.intl.xiaomi.com", description = "Xiaomi SDK config domain" },
    { value = "api.ad.intl.xiaomi.com", description = "Xiaomi API domain" },
    { value = "api.eu-west-1.aiv-delivery.net", description = "AIV delivery domain" },
    { value = "global.telemetry.insights.video.a2z.com", description = "Amazon telemetry domain" },
    { value = "device-metrics-us-2.amazon.com", description = "Amazon device metrics domain" },
    { value = "fls-eu.amazon.co.uk", description = "Amazon FLS domain" },
    { value = "fls-eu.amazon.com", description = "Amazon FLS domain" },
    { value = "sdk.split.io", description = "Split.io SDK domain" },
    { value = "incoming.telemetry.mozilla.org", description = "Mozilla telemetry domain" },
    { value = "securepubads.g.doubleclick.net", description = "Google Ads domain" },
    { value = "www.googletagmanager.com", description = "Google Tag Manager domain" },
    { value = "logx.optimizely.com", description = "Optimizely logging domain" },
    { value = "mobile-collector.newrelic.com", description = "New Relic mobile collector domain" },
    { value = "api2.branch.io", description = "Branch API domain" },
    { value = "ping.chartbeat.net", description = "Chartbeat ping domain" },
    { value = "quantcast.mgr.consensu.org", description = "Quantcast consent domain" },
    { value = "nexus.ensighten.com", description = "Ensighten nexus domain" },
    { value = "js.monitor.azure.com", description = "Microsoft JS monitor domain" },
    { value = "js.hs-scripts.com", description = "HubSpot JS scripts domain" },
    { value = "s2s.singular.net", description = "Singular S2S domain" },
    { value = "device-metrics-us.amazon.com", description = "Amazon device metrics domain" },
    { value = "ichnaea-web.netflix.com", description = "Netflix Ichnaea web domain" },
    { value = "www.google-analytics.com", description = "Google Analytics domain" },
    { value = "mobileanalytics.us-east-1.amazonaws.com", description = "Amazon Mobile Analytics domain" },
    { value = "cws.conviva.com", description = "Conviva CWS domain" },
    { value = "tracker.coppersurfer.tk", description = "Copper Surfer tracker domain" }
  ]
}