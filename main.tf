
locals {
  boolorgpols_map         = { for index, boolorgpol in var.boolorgpols : "${index}" => boolorgpol }
  listorgpols_map         = { for index, listorgpol in var.listorgpols : "${index}" => listorgpol }
  vpc_uri                 = "projects/${var.project_id}/global/networks/${var.vpc_infra}"
  service_type_psc        = "psc-neg"
  service_type_inet       = "inet-neg"
  service_type_serverless = "serverless-neg"
}

terraform {
  required_version = ">= 1.8"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.45.2"
      #      version = "~> 6.0.0"
    }
  }
}


# ===== APIs and org policies =====

module "project" {
  source         = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/project?ref=v28.0.0"
  name           = var.project_id
  project_create = false
  services       = var.services
}

# enforced / not enforced type policies
module "bool_org_policy" {
  source      = "terraform-google-modules/org-policy/google"
  for_each    = local.boolorgpols_map
  policy_for  = "project"
  project_id  = var.project_id
  constraint  = "constraints/compute.${each.value}"
  policy_type = "boolean"
  enforce     = false
  #  version     = "~> 5.0.0"
}

# allow all / deny all type org policies
module "list_org_policy" {
  source      = "terraform-google-modules/org-policy/google"
  for_each    = local.listorgpols_map
  policy_for  = "project"
  project_id  = var.project_id
  constraint  = "constraints/compute.${each.value}"
  policy_type = "list"
  enforce     = false
  #  version     = "~> 5.0.0"
}


# ======= Timer to give APIs time to fully enable =======
resource "time_sleep" "wait_60_seconds" {
  create_duration = "60s"
  depends_on      = [module.project, module.bool_org_policy, module.list_org_policy]
}


# ===== VPCs, subnets and VMs =====

# VPCs for DC, Hub and Spoke
module "vpc-spoke" {
  count      = var.create_vpcs ? 1 : 0
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-vpc?ref=v28.0.0"
  project_id = var.project_id
  name       = var.spoke_network
  subnets    = var.spoke_subnets
  depends_on = [time_sleep.wait_60_seconds]
}

module "vpc-hub" {
  count      = var.create_vpcs ? 1 : 0
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-vpc?ref=v28.0.0"
  project_id = var.project_id
  name       = var.hub_network
  subnets    = var.hub_subnets
  depends_on = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

module "vpc-dc" {
  count      = var.create_vpcs ? 1 : 0
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-vpc?ref=v28.0.0"
  project_id = var.project_id
  name       = var.dc_network
  subnets    = var.dc_subnets
  depends_on = [time_sleep.wait_60_seconds]
}

# VPC Peering from Hub to Spoke
resource "google_compute_network_peering" "peering-vpc1-vpc2" {
  name                 = "peering-${var.hub_network}-${var.spoke_network}"
  network              = "projects/${var.project_id}/global/networks/${var.hub_network}"
  peer_network         = "projects/${var.project_id}/global/networks/${var.spoke_network}"
  export_custom_routes = true
  import_custom_routes = true
  depends_on           = [time_sleep.wait_60_seconds, module.vpc-hub]
}

resource "google_compute_network_peering" "peering-vpc2-vpc1" {
  name                 = "peering-${var.spoke_network}-${var.hub_network}"
  network              = "projects/${var.project_id}/global/networks/${var.spoke_network}"
  peer_network         = "projects/${var.project_id}/global/networks/${var.hub_network}"
  export_custom_routes = true
  import_custom_routes = true
  depends_on           = [time_sleep.wait_60_seconds, module.vpc-hub]
}

# NAT for GitHub Enterprise Server to access image
module "cldnat-ghes" {
  source         = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-cloudnat?ref=v28.0.0"
  project_id     = var.project_id
  region         = var.dc_ghes_config.region
  name           = "${var.cldnat_name}-${var.dc_network}"
  router_network = var.dc_network
  depends_on     = [time_sleep.wait_60_seconds, module.vpc-dc]
}

# GitHub Enterprise Server
module "dc-ghes-vm" {
  source      = "./modules/ghes-vm"
  project_id  = var.project_id
  ghes_config = var.dc_ghes_config
  depends_on  = [module.vpc-dc, module.vpc-hub, module.vpc-spoke, time_sleep.wait_60_seconds]
}

# VPN between hub and DC
module "vpn-vpc" {
  count      = var.create_vpcs ? 1 : 0
  source     = "./modules/vpn-vpc"
  project_id = var.project_id
  vpn_config = var.vpn_config
  depends_on = [module.vpc-dc, module.vpc-hub, module.vpc-spoke, time_sleep.wait_60_seconds]
}

# Windows Bastion host for testing
module "win_bastion_vm" {
  source         = "./modules/windows-bastion-vm"
  project_id     = var.project_id
  bastion_config = var.bastion_config
  depends_on     = [module.vpc-dc, module.vpc-hub, module.vpc-spoke, time_sleep.wait_60_seconds]
}

# NAT for GitHub Enterprise Server to access image
module "cldnat_win_bastion" {
  source         = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-cloudnat?ref=v28.0.0"
  project_id     = var.project_id
  region         = var.bastion_config.region
  name           = "${var.cldnat_name}-${var.bastion_config.vpc}"
  router_network = var.bastion_config.vpc
  depends_on     = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

# proxy-only subnet for the load balancers in parts 3 & 4
resource "google_compute_subnetwork" "proxy-subnet-for-lbs" {
  project       = var.project_id
  name          = var.proxy_only_subnet_name
  ip_cidr_range = var.proxy_only_subnet_cidr
  region        = var.region_infra
  #  region        = data.google_compute_subnetwork.subnet_infra.region
  purpose    = "REGIONAL_MANAGED_PROXY"
  role       = "ACTIVE"
  network    = var.spoke_network
  depends_on = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

# NAT and Cloud Router for Internet NEG in part 4
resource "google_compute_router" "proxy_subnet_nat_router" {
  project    = var.project_id
  name       = "cldrtr-for-proxy-subnet"
  region     = var.region_infra
  network    = var.spoke_network
  depends_on = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

resource "google_compute_router_nat" "proxy_subnet_nat" {
  project                            = var.project_id
  name                               = "natgw-proxy-subnet"
  router                             = google_compute_router.proxy_subnet_nat_router.name
  region                             = google_compute_router.proxy_subnet_nat_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = var.proxy_only_subnet_name
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
  endpoint_types = ["ENDPOINT_TYPE_MANAGED_PROXY_LB"]
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  depends_on = [time_sleep.wait_60_seconds, google_compute_subnetwork.proxy-subnet-for-lbs]
}


# ======= NORTHBOUND INFRASTRUCTURE =========

# ===== Northbound Internal Application Load Balancer & associated resources =====

# ======= Common Components such as Northbound PSC NEG and cert ======= 
# psc neg Northbound Internal Application Load Balancer
resource "google_compute_region_network_endpoint_group" "psc_neg_nb" {
  project               = var.project_id
  name                  = "${local.service_type_psc}-nb"
  region                = var.region_infra
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = var.svc_sa
  network               = var.vpc_infra
  subnetwork            = var.subnet_infra
  depends_on            = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

# cert for Northbound Internal Application Load Balancer
resource "google_compute_region_ssl_certificate" "cert" {
  project     = var.project_id
  region      = var.region_infra
  name_prefix = "cert-${var.svc_name}-nb"
  description = ""
  private_key = file(var.cert_private_key_path)
  certificate = file(var.cert_path)
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [time_sleep.wait_60_seconds]
}




# ======= Components for Northbound Internal Application Load Balancer with cert ======= 

# create static internal IP address used to reach the load balancer
resource "google_compute_address" "lb-static-ip" {
  project      = var.project_id
  region       = var.region_infra
  name         = "${var.lb_static_ip_name_prefix}-${var.lb_name}"
  address_type = "INTERNAL"
  ip_version   = "IPV4"
  subnetwork   = var.subnet_infra
  depends_on   = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

# backend service for Northbound Internal Application Load Balancer
resource "google_compute_region_backend_service" "backend-service" {
  project               = var.project_id
  name                  = "${var.backend_service_name_prefix}-${var.lb_name}"
  region                = var.region_infra
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "INTERNAL_MANAGED"
  timeout_sec           = 3600
  backend {
    group           = google_compute_region_network_endpoint_group.psc_neg_nb.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# url map for Northbound Internal Application Load Balancer
resource "google_compute_region_url_map" "url-map" {
  project         = var.project_id
  name            = var.lb_name
  region          = var.region_infra
  default_service = google_compute_region_backend_service.backend-service.id
  depends_on      = [time_sleep.wait_60_seconds]
}

# https proxy for Northbound Internal Application Load Balancer
resource "google_compute_region_target_https_proxy" "proxy-https" {
  project          = var.project_id
  name             = "${var.lb_https_proxy_name_prefix}-${var.lb_name}"
  region           = var.region_infra
  url_map          = google_compute_region_url_map.url-map.id
  ssl_certificates = [google_compute_region_ssl_certificate.cert.id]
  depends_on       = [time_sleep.wait_60_seconds]
}

# https forwarding rule for Northbound Internal Application Load Balancer 
resource "google_compute_forwarding_rule" "forwarding-rule-https" {
  project               = var.project_id
  name                  = "${var.forwarding_rule_name_prefix}-https-${var.lb_name}"
  region                = var.region_infra
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  port_range            = "443"
  network               = var.vpc_infra
  target                = google_compute_region_target_https_proxy.proxy-https.id
  ip_address            = google_compute_address.lb-static-ip.id
  subnetwork            = var.subnet_infra
  depends_on            = [time_sleep.wait_60_seconds, google_compute_subnetwork.proxy-subnet-for-lbs]
}

# DNS record for Northbound Internal Application Load Balancer
module "private-dns" {
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/dns?ref=v26.0.0"
  project_id = var.project_id
  name       = replace(var.svc_dns_domain, ".", "-")
  zone_config = {
    domain = "${var.svc_dns_domain}."
    private = {
      client_networks = [local.vpc_uri]
    }
  }
  recordsets = {
    "A ${var.svc_name}" = { records = [google_compute_address.lb-static-ip.address] }
  }
  depends_on = [time_sleep.wait_60_seconds, module.vpc-spoke]
}




# ======= Components for Northbound External Application Load Balancer with cert ======= 

# cert for Northbound External Application Load Balancer
resource "google_compute_region_ssl_certificate" "cert-ext" {
  project     = var.project_id
  region      = var.region_infra
  name_prefix = "cert-looker-nb-ext"
  description = ""
  private_key = file(var.cert_private_key_path)
  certificate = file(var.cert_path)
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# static external IP address for Northbound External Application Load Balancer
resource "google_compute_address" "lb-static-ip-ext" {
  project      = var.project_id
  region       = var.region_infra
  name         = "${var.lb_static_ip_name_prefix}-${var.lb_name}-ext"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  depends_on   = [time_sleep.wait_60_seconds]
}

# Cloud Armor policy to allow IPs for Northbound External Application Load Balancer
resource "google_compute_security_policy" "cloudarmor-policy" {
  #resource "google_compute_region_security_policy" "cloudarmor-policy" {
  #  provider = google-beta  
  project = var.project_id
  name    = "${var.cloudarmor_policy_name_prefix}-${var.lb_name}"
  rule {
    action   = "allow"
    priority = "10000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = var.ext_allowed_ips
      }
    }
    description = "Trusted IPs"
  }
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# backend service for Northbound External Application Load Balancer
resource "google_compute_region_backend_service" "backend-service-ext" {
  #  provider              = google-beta
  project               = var.project_id
  name                  = "${var.backend_service_name_prefix}-${var.lb_name}-ext"
  region                = var.region_infra
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 3600
  #  security_policy         = google_compute_security_policy.cloudarmor-policy.id
  backend {
    group           = google_compute_region_network_endpoint_group.psc_neg_nb.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# url map for Northbound External Application Load Balancer
resource "google_compute_region_url_map" "url-map-ext" {
  project         = var.project_id
  name            = "${var.lb_name}-ext"
  region          = var.region_infra
  default_service = google_compute_region_backend_service.backend-service-ext.id
  depends_on      = [time_sleep.wait_60_seconds]
}

# https proxy for Northbound External Application Load Balancer
resource "google_compute_region_target_https_proxy" "proxy-https-ext" {
  project          = var.project_id
  name             = "${var.lb_https_proxy_name_prefix}-${var.lb_name}-ext"
  region           = var.region_infra
  url_map          = google_compute_region_url_map.url-map-ext.id
  ssl_certificates = [google_compute_region_ssl_certificate.cert.id]
#  ssl_certificates = [google_compute_region_ssl_certificate.cert-ext.id]
  depends_on       = [time_sleep.wait_60_seconds]
}

# https forwarding rule for Northbound External Application Load Balancer
resource "google_compute_forwarding_rule" "forwarding-rule-https-ext" {
  project               = var.project_id
  name                  = "${var.forwarding_rule_name_prefix}-https-${var.lb_name}-ext"
  region                = var.region_infra
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  network               = var.vpc_infra
  target                = google_compute_region_target_https_proxy.proxy-https-ext.id
  ip_address            = google_compute_address.lb-static-ip-ext.id
  depends_on            = [time_sleep.wait_60_seconds, google_compute_subnetwork.proxy-subnet-for-lbs]
}



# ======= Components for Northbound Internal TCP Proxy Load Balancer without cert ======= 

# backend service for Northbound Internal TCP Proxy Load Balancer without cert
resource "google_compute_region_backend_service" "bes" {
  project                         = var.project_id
  name                            = "${var.lb_name}-tcp"
  region                          = var.region_infra
  protocol                        = "TCP"
  load_balancing_scheme           = "INTERNAL_MANAGED"
  connection_draining_timeout_sec = 0
  log_config {
    enable      = true
    sample_rate = 1
    #    optional_mode = "INCLUDE_ALL_OPTIONAL"
  }
  backend {
    group          = google_compute_region_network_endpoint_group.psc_neg_nb.id
    balancing_mode = "UTILIZATION"
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# tcp proxy for Northbound Internal TCP Proxy Load Balancer without cert
resource "google_compute_region_target_tcp_proxy" "tcp_proxy" {
  project         = var.project_id
  name            = "${var.lb_tcp_proxy_name_prefix}-${var.lb_name}"
  region          = var.region_infra
  backend_service = google_compute_region_backend_service.bes.id
  depends_on      = [time_sleep.wait_60_seconds]
}

# static internal IP address for Northbound Internal TCP Proxy Load Balancer without cert
resource "google_compute_address" "lb-static-ip-tcp" {
  project      = var.project_id
  region       = var.region_infra
  name         = "${var.lb_static_ip_name_prefix}-${google_compute_region_target_tcp_proxy.tcp_proxy.name}"
  address_type = "INTERNAL"
  ip_version   = "IPV4"
  subnetwork   = var.subnet_infra
  depends_on   = [time_sleep.wait_60_seconds]
}

# https forwarding rule for Northbound Internal TCP Proxy Load Balancer without cert
resource "google_compute_forwarding_rule" "fr" {
  project               = var.project_id
  ip_address            = google_compute_address.lb-static-ip-tcp.address
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  name                  = "${var.forwarding_rule_name_prefix}-tcp-${var.lb_name}"
  network               = var.vpc_infra
  network_tier          = "PREMIUM"
  port_range            = "443"
  region                = var.region_infra
  subnetwork            = var.subnet_infra
  target                = google_compute_region_target_tcp_proxy.tcp_proxy.id
  depends_on            = [time_sleep.wait_60_seconds, google_compute_subnetwork.proxy-subnet-for-lbs]
}


# ======= SOUTHBOUND INFRASTRUCTURE =========
# ======= Network Endpoint Group (NEG) ======= 
# ======= Internet, Serverless or PSC depending on configuration ======= 

# == Original NEG and endpoint - Internet NEG
resource "google_compute_region_network_endpoint_group" "inet_neg" {
  count                 = var.psc_sb_infra_config.service_type == local.service_type_inet ? 1 : 0
  project               = var.project_id
  name                  = "${local.service_type_inet}-sb"
  region                = var.region_infra
  network               = var.vpc_infra
  network_endpoint_type = "INTERNET_FQDN_PORT"
  depends_on            = [time_sleep.wait_60_seconds, google_compute_subnetwork.proxy-subnet-for-lbs]
}

resource "google_compute_region_network_endpoint" "inet-ep" {
  count                         = var.psc_sb_infra_config.service_type == local.service_type_inet ? 1 : 0
  project                       = var.project_id
  region_network_endpoint_group = google_compute_region_network_endpoint_group.inet_neg[0].name
  region                        = var.region_infra
  fqdn                          = var.psc_sb_infra_config.inet_neg_fqdn_domain
  #  fqdn                          = "${var.psc_sb_infra_config.fqdn_host}.${var.psc_sb_infra_config.inet_neg_fqdn_domain}"
  port       = var.psc_sb_infra_config.port
  depends_on = [time_sleep.wait_60_seconds]
}

# == Serverless NEG - Cloud Run
resource "google_compute_region_network_endpoint_group" "srvrless_cr_neg" {
  count                 = var.psc_sb_infra_config.service_type == local.service_type_serverless ? 1 : 0
  project               = var.project_id
  name                  = "${local.service_type_serverless}-${var.svc_name}"
  network_endpoint_type = "SERVERLESS"
  region                = var.region_infra
  cloud_run {
    service = var.psc_sb_infra_config.serverless_instance_name
  }
  depends_on = [time_sleep.wait_60_seconds]
}

# == PSC NEG
resource "google_compute_region_network_endpoint_group" "psc_neg_sb" {
  count                 = var.psc_sb_infra_config.service_type == local.service_type_psc ? 1 : 0
  project               = var.project_id
  name                  = "${local.service_type_psc}-sb"
  region                = var.region_infra
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = var.psc_sb_infra_config.psc_neg_sa_uri
  #  psc_data {
  #    producer_port = "${var.psc_sb_infra_config.port}"
  #  }
  network    = var.vpc_infra
  subnetwork = var.psc_sb_infra_config.psc_neg_subnet
  depends_on = [time_sleep.wait_60_seconds]
}

resource "google_compute_region_backend_service" "bes_sb" {
  project                         = var.project_id
  name                            = "${replace(var.lb_name, "nb", "sb")}-tcp"
  region                          = var.region_infra
  protocol                        = "TCP"
  load_balancing_scheme           = "INTERNAL_MANAGED"
  connection_draining_timeout_sec = 0
  log_config {
    enable      = true
    sample_rate = 1
  }
  backend {
    group          = var.psc_sb_infra_config.service_type == local.service_type_psc ? google_compute_region_network_endpoint_group.psc_neg_sb[0].id : var.psc_sb_infra_config.service_type == local.service_type_inet ? google_compute_region_network_endpoint_group.inet_neg[0].id : google_compute_region_network_endpoint_group.srvrless_cr_neg[0].id
    balancing_mode = "UTILIZATION"
  }
  depends_on = [time_sleep.wait_60_seconds]
}

resource "google_compute_region_target_tcp_proxy" "tcp_proxy_sb" {
  project         = var.project_id
  name            = "${var.lb_tcp_proxy_name_prefix}-${replace(var.lb_name, "nb", "sb")}"
  region          = var.region_infra
  backend_service = google_compute_region_backend_service.bes_sb.id
  depends_on      = [time_sleep.wait_60_seconds]
}

resource "google_compute_address" "ip_address_internal" {
  project      = var.project_id
  name         = "psc-sa-lb-forwarding-rule-ip"
  subnetwork   = var.subnet_infra
  address_type = "INTERNAL"
  region       = var.region_infra
  depends_on   = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

resource "google_compute_forwarding_rule" "fr_sb" {
  project = var.project_id
  #  ip_address            = "10.1.1.19"
  ip_address            = google_compute_address.ip_address_internal.address
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  name                  = "${var.forwarding_rule_name_prefix}-tcp-${replace(var.lb_name, "nb", "sb")}"
  #  network               = var.psc_sb_infra_config.vpc
  network      = var.vpc_infra
  network_tier = "PREMIUM"
  port_range   = var.psc_sb_infra_config.port
  #  region                = var.psc_sb_infra_config.region
  region = var.region_infra
  #   subnetwork            = var.psc_sb_infra_config.forwarding_rule_subnet
  subnetwork = var.subnet_infra
  target     = google_compute_region_target_tcp_proxy.tcp_proxy_sb.id
  depends_on = [google_compute_address.ip_address_internal, time_sleep.wait_60_seconds]
}


resource "google_compute_subnetwork" "psc_sa_nat_subnet" {
  project = var.project_id
  name    = "psc-sa-nat-subnet-${var.svc_name}"
  #  region        = var.psc_sb_infra_config.region
  #  network       = var.psc_sb_infra_config.vpc
  region        = var.region_infra
  network       = var.vpc_infra
  purpose       = "PRIVATE_SERVICE_CONNECT"
  ip_cidr_range = var.psc_sb_infra_config.service_attachment_nat_iprange
  depends_on    = [time_sleep.wait_60_seconds, module.vpc-spoke]
}

resource "google_compute_service_attachment" "psc_sa_sb" {
  project               = var.project_id
  name                  = "svcattachment-${var.svc_name}-${var.psc_sa_num}"
  region                = var.region_infra
  enable_proxy_protocol = false
  connection_preference = "ACCEPT_AUTOMATIC"
  nat_subnets           = [google_compute_subnetwork.psc_sa_nat_subnet.id]
  target_service        = google_compute_forwarding_rule.fr.id
  depends_on            = [time_sleep.wait_60_seconds]
}


# ======= Configure Looker to allow the VPC ======= 

module "gcloud_set_prj" {
  source                 = "terraform-google-modules/gcloud/google"
  version                = "~> 3.5"
  platform               = "linux"
  create_cmd_entrypoint  = "gcloud"
  create_cmd_body        = "config set project ${var.project_id}"
  destroy_cmd_entrypoint = ""
  destroy_cmd_body       = ""
  module_depends_on      = [google_compute_forwarding_rule.fr_sb]
}

module "gcloud_looker_update_allowed_vpcs" {
  source                = "terraform-google-modules/gcloud/google"
  version               = "~> 3.5"
  platform              = "linux"
  create_cmd_entrypoint = "gcloud"
  #  create_cmd_body        = "looker instances update ${var.svc_instance_name} --psc-allowed-vpcs ${local.vpc_uri} --region ${var.region_infra}"
  create_cmd_body        = "looker instances update ${var.svc_instance_name} --psc-allowed-vpcs ${local.vpc_uri} --region ${var.region_infra} --quiet"
  destroy_cmd_entrypoint = ""
  destroy_cmd_body       = ""
  module_depends_on      = [google_compute_forwarding_rule.fr_sb]
}

module "gcloud_looker_update_svc_attachment_uri" {
  source                = "terraform-google-modules/gcloud/google"
  version               = "~> 3.5"
  platform              = "linux"
  create_cmd_entrypoint = "gcloud"
  #  create_cmd_body        = "looker instances update ${var.svc_instance_name} --region ${var.region_infra} --psc-service-attachment domain=${var.psc_sb_infra_config.inet_neg_fqdn_domain},attachment=${google_compute_service_attachment.psc_sa_sb.self_link}"
  create_cmd_body        = "looker instances update ${var.svc_instance_name} --region ${var.region_infra} --psc-service-attachment domain=${var.psc_sb_infra_config.inet_neg_fqdn_domain},attachment=${google_compute_service_attachment.psc_sa_sb.self_link} --quiet"
  destroy_cmd_entrypoint = ""
  destroy_cmd_body       = ""
  module_depends_on      = [google_compute_forwarding_rule.fr_sb]
}

