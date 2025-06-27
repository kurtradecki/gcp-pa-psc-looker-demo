resource "google_compute_instance" "windows-server-2022-bastion1" {
  project = var.project_id
  boot_disk {
    auto_delete = true
    device_name = var.bastion_config.vm_name

    initialize_params {
      image = "projects/windows-cloud/global/images/windows-server-2022-dc-v20250123"
      size  = 50
      type  = "pd-balanced"
    }

    mode = "READ_WRITE"
  }

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false
  machine_type = "e2-medium"

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "true"
  }

  name = var.bastion_config.vm_name

  network_interface {
    queue_count = 0
    stack_type  = "IPV4_ONLY"
    subnetwork  = "projects/${var.project_id}/regions/${var.bastion_config.region}/subnetworks/${var.bastion_config.subnet}"
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  zone = var.bastion_config.zone
}

# create Firewall rules to allow IAP to bastion host
resource "google_compute_firewall" "allow-rdp-bastion" {
  project = var.project_id
  name    = var.bastion_config.fw_name
  direction = "INGRESS"
  priority  = "1000"
  network   = var.bastion_config.vpc
  allow {
    protocol = "tcp"
  }
  source_ranges = var.bastion_config.fw_ranges
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}