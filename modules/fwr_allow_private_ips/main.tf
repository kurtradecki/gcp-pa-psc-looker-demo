# create Firewall rule to allow ingress from all private IPs
resource "google_compute_firewall" "allow_private_ips" {
  project = var.project_id
  name    = "fwr-allow-private-ips-${var.vpc}"
  #  description = ""
  direction = "INGRESS"
  priority  = "1000"
  network   = var.vpc
  allow {
    protocol = "all"
  }
  source_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}