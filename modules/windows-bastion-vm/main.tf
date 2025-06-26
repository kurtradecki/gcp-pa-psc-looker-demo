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
  /*
  labels = {
    goog-ec-src           = "vm_add-tf"
    goog-gcp-marketplace  = ""
    goog-ops-agent-policy = "v2-x86-template-1-4-0"
  }
*/
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

  /*
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  service_account {
    email  = "332986205049-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
*/

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  zone = var.bastion_config.zone
}

/*
module "ops_agent_policy" {
  source          = "github.com/terraform-google-modules/terraform-google-cloud-operations/modules/ops-agent-policy"
  project         = var.project_id
  zone            = var.bastion_config.zone
  assignment_id   = "goog-ops-agent-v2-x86-template-1-4-0-${var.bastion_config.zone}"
  agents_rule = {
    package_state = "installed"
    version = "latest"
  }
  instance_filter = {
    all = false
    inclusion_labels = [{
      labels = {
        goog-ops-agent-policy = "v2-x86-template-1-4-0"
      }
    }]
  }
}
*/

# create Firewall rules to allow IAP to bastion host
resource "google_compute_firewall" "allow-rdp-bastion" {
  project = var.project_id
  name    = var.bastion_config.fw_name
  #  description = ""
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