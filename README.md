# Cloudflare Zero Trust — Terraform

Terraform configuration for a Cloudflare Zero Trust deployment. Provider: `cloudflare/cloudflare ~> 5.22.0`.

## Credentials

Create `terraform.tfvars` (never commit it):

```hcl
cloudflare_account_id = "your-account-id"
cloudflare_api_token  = "your-api-token"
cloudflare_zone_id    = "your-zone-id"
```

Required API token permissions: Zero Trust Edit, Access Device Posture Edit.

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Configuration files

| File | Contents |
|---|---|
| `main.tf` | Provider config, variables, category/app data sources |
| `zt_dns_gateway.tf` | DNS Gateway rules (security threats, geo-blocking, TLD blocks, content filtering) |
| `zt_http_gateway.tf` | HTTP Gateway rules (content filtering, geo-blocking, file/MIME blocks, isolation, DLP) |
| `zt_lists.tf` | Gateway lists (IP, domain, email) referenced by rules |
| `zt_posture.tf` | Device posture rules (OS version, disk encryption, firewall, antivirus, app checks) |
| `zt_groups.tf` | Zero Trust Access groups |
| `zt_dlp_profiles.tf` | DLP custom profiles and entries (MCP detection, keys/tokens) |
| `zt_digital_experience.tf` | DEX rules (Desktop, Mobile) and DEX tests |

## Cleanup script

`cleanup-zero-trust.py` removes all managed resources from the account via the API — useful for resetting state before a fresh `terraform apply`.

```bash
# Preview (no deletions)
DRY_RUN=true python3 cleanup-zero-trust.py

# Delete everything
python3 cleanup-zero-trust.py
```

Resources removed (in order): HTTP/DNS/Network gateway rules, gateway lists, device posture rules, DEX tests, DLP custom entries, DLP custom profiles.

Credentials are read automatically from `terraform.tfvars`.
