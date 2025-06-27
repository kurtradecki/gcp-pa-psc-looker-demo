terraform {
  required_version = ">= 1.10"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.11.2"
    }
  }
}

data "google_compute_network" "vpc1" {
  project = var.project_id
  name    = var.vpn_config.vpc1
}

data "google_compute_network" "vpc2" {
  project = var.project_id
  name    = var.vpn_config.vpc2
}

# VPNGW, tunnels and CR from connectivity VPC, called "hub" in this script, to hub VPC in east-1
module "vpn-1" {
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-vpn-ha?ref=v36.0.0"
  project_id = var.project_id
  region     = var.vpn_config.region
  network    = data.google_compute_network.vpc1.self_link
  name       = "vpngw-${data.google_compute_network.vpc1.name}"
  peer_gateways = {
    default = { gcp = module.vpn-2.self_link }
  }
  router_config = {
    asn  = 64514
    name = "cldrtr-${data.google_compute_network.vpc1.name}-${var.vpn_config.region}-internal"
    custom_advertise = {
      all_subnets = true
      ip_ranges = var.vpn_config.vpc1-advertised-ranges
    }
  }
  tunnels = {
    remote-0 = {
      bgp_peer = {
        address = "169.254.1.1"
        asn     = 64513
      }
      bgp_session_range     = "169.254.1.2/30"
      vpn_gateway_interface = 0
    }
    remote-1 = {
      bgp_peer = {
        address = "169.254.2.1"
        asn     = 64513
      }
      bgp_session_range     = "169.254.2.2/30"
      vpn_gateway_interface = 1
    }
  }
}

# VPNGW, tunnels and CR from hub VPC in east-1 to connectivity VPC, called "hub" in this script
module "vpn-2" {
  source     = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/net-vpn-ha?ref=v36.0.0"
  project_id = var.project_id
  region     = var.vpn_config.region
  network    = data.google_compute_network.vpc2.self_link
  name       = "vpngw-${data.google_compute_network.vpc2.name}"
  router_config = {
    asn  = 64513
    name = "cldrtr-${data.google_compute_network.vpc2.name}-${var.vpn_config.region}-internal"
    custom_advertise = {
      all_subnets = true
      ip_ranges = var.vpn_config.vpc2-advertised-ranges
    }
  }
  peer_gateways = {
    default = { gcp = module.vpn-1.self_link }
  }
  tunnels = {
    remote-0 = {
      bgp_peer = {
        address = "169.254.1.2"
        asn     = 64514
      }
      bgp_session_range     = "169.254.1.1/30"
      shared_secret         = module.vpn-1.random_secret
      vpn_gateway_interface = 0
    }
    remote-1 = {
      bgp_peer = {
        address = "169.254.2.2"
        asn     = 64514
      }
      bgp_session_range     = "169.254.2.1/30"
      shared_secret         = module.vpn-1.random_secret
      vpn_gateway_interface = 1
    }
  }
}