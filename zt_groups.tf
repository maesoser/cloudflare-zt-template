resource "cloudflare_zero_trust_access_group" "test_employees" {
  account_id = var.cloudflare_account_id
  name       = "Test Employees"
  include = [
    { email = { email = "john@example.com" } },
    { email = { email = "alice@example.com" } },
    { email = { email = "bob@example.com" } }
  ]
}
