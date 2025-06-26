resource "google_compute_disk" "git_disk" {
  name                      = var.ghes_config.diskname
  physical_block_size_bytes = 4096
  project                   = var.project_id
  size                      = 500
  type                      = "pd-ssd"
  zone                      = var.ghes_config.zone
}

resource "google_compute_instance" "github_enterprise_vm" {
  attached_disk {
    device_name = "persistent-disk-1"
    mode        = "READ_WRITE"
    source      = google_compute_disk.git_disk.self_link
    #    source      = "https://www.googleapis.com/compute/v1/projects/prj-ice-looker-testing/zones/us-central1-a/disks/git-disk3"
  }
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/github-enterprise-public/global/images/github-enterprise-3-15-1"
      size  = 401
      type  = "pd-standard"
    }
    mode = "READ_WRITE"
    #    source = "https://www.googleapis.com/compute/v1/projects/${local.projectid}/zones/${local.zone}/disks/${local.githubservername}"
  }
  machine_type = "n1-standard-8"
  metadata = {
    serial-port-enable = "1"
  }
  name = var.ghes_config.githubservername
  network_interface {
    network = "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/networks/${var.ghes_config.vpcname}"
    #    network_ip         = "10.23.1.3"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/${var.project_id}/regions/${var.ghes_config.region}/subnetworks/${var.ghes_config.subnetname}"
    subnetwork_project = var.project_id
  }
  project = var.project_id
  /*
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }
  service_account {
    email  = "864603995815-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
*/
  zone = var.ghes_config.zone
}

module "fwr_allow_private_ips" {
  source     = "../fwr_allow_private_ips"
  project_id = var.project_id
  vpc        = var.ghes_config.vpcname
}