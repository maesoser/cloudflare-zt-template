resource "cloudflare_zero_trust_device_posture_rule" "os_chromeos_version" {
  account_id  = var.cloudflare_account_id
  name        = "ChromeOS 118"
  type        = "os_version"
  description = "Require ChromeOS 118 or higher"
  schedule    = "5m"
  match       = [{ platform = "chromeos" }]

  input = {
    version  = "118.15604.45"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_debian_12" {
  account_id  = var.cloudflare_account_id
  name        = "Debian 12"
  type        = "os_version"
  description = "Require Debian 12 or higher"
  match       = [{ platform = "linux" }]

  input = {
    os_distro_name     = "debian"
    version            = "6.1.0"
    os_distro_revision = "12.0.0"
    operator           = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_debian_13" {
  account_id  = var.cloudflare_account_id
  name        = "Debian 13"
  type        = "os_version"
  description = "Require Debian 13 or higher"
  match       = [{ platform = "linux" }]

  input = {
    os_distro_name     = "debian"
    version            = "6.1.0"
    os_distro_revision = "13.3.0"
    operator           = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_ios_18" {
  account_id  = var.cloudflare_account_id
  name        = "iOS 18"
  type        = "os_version"
  description = "Require iOS 18 or higher"
  match       = [{ platform = "ios" }]

  input = {
    version  = "18.0.0"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_ios_26" {
  account_id  = var.cloudflare_account_id
  name        = "iOS 26"
  type        = "os_version"
  description = "Require iOS 26 or higher"
  match       = [{ platform = "ios" }]

  input = {
    version  = "26.0.0"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_android_15" {
  account_id  = var.cloudflare_account_id
  name        = "Android 15"
  type        = "os_version"
  description = "Require Android 15 or higher"
  match       = [{ platform = "android" }]

  input = {
    version  = "15.0.0"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_android_16" {
  account_id  = var.cloudflare_account_id
  name        = "Android 16"
  type        = "os_version"
  description = "Require Android 16 or higher"
  match       = [{ platform = "android" }]

  input = {
    version  = "16.0.0"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "os_windows_11" {
  account_id  = var.cloudflare_account_id
  name        = "Windows 11"
  type        = "os_version"
  description = "Require Windows 11 or higher"
  match       = [{ platform = "windows" }]

  input = {
    version  = "11.0.0"
    operator = ">="
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "gateway_enabled" {
  account_id  = var.cloudflare_account_id
  name        = "Gateway Enabled"
  type        = "gateway"
  description = "Require Cloudflare Gateway to be enabled"
}

resource "cloudflare_zero_trust_device_posture_rule" "disk_encryption_linux" {
  account_id  = var.cloudflare_account_id
  name        = "Linux Disk Encryption"
  type        = "disk_encryption"
  description = "Require disk encryption on Linux devices"
  match       = [{ platform = "linux" }]

  input = {
    check_disks = []
    require_all = true
  }

}

resource "cloudflare_zero_trust_device_posture_rule" "disk_encryption_macos" {
  account_id  = var.cloudflare_account_id
  name        = "macOS Disk Encryption"
  type        = "disk_encryption"
  description = "Require disk encryption (FileVault) on macOS devices"
  match       = [{ platform = "mac" }]

  input = {
    check_disks = []
    require_all = true
  }

}

resource "cloudflare_zero_trust_device_posture_rule" "disk_encryption_windows" {
  account_id  = var.cloudflare_account_id
  name        = "Windows Disk Encryption"
  type        = "disk_encryption"
  description = "Require disk encryption (BitLocker) on Windows devices"
  match       = [{ platform = "windows" }]

  input = {
    check_disks = []
    require_all = true
  }

}

resource "cloudflare_zero_trust_device_posture_rule" "firewall_macos" {
  account_id  = var.cloudflare_account_id
  name        = "macOS Firewall"
  type        = "firewall"
  description = "Require firewall to be enabled on macOS devices"
  match       = [{ platform = "mac" }]

  input = {
    enabled = true
  }
}


resource "cloudflare_zero_trust_device_posture_rule" "firewall_windows" {
  account_id  = var.cloudflare_account_id
  name        = "Windows Firewall"
  type        = "firewall"
  description = "Require firewall to be enabled on Windows devices"
  match       = [{ platform = "windows" }]

  input = {
    enabled = true
  }
}

resource "cloudflare_zero_trust_device_posture_rule" "antivirus_windows" {
  account_id  = var.cloudflare_account_id
  name        = "Windows Antivirus"
  type        = "antivirus"
  description = "Require Antivirus to be enabled on Windows devices"
  match       = [{ platform = "windows" }]

  input = {
    enabled = true
  }
}


resource "cloudflare_zero_trust_device_posture_rule" "application_check_crowdstrike_windows" {
  account_id  = var.cloudflare_account_id
  name        = "Windows Crowdstrike"
  description = "Require Crowdstrike to be running on Windows devices"
  type        = "application"
  schedule    = "5m"
  match       = [{ platform = "windows" }]

  input = {
    path = "C:\\Program Files\\CrowdStrike\\CSFalconService.exe"
  }

}
