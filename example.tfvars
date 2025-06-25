# This script builds a static, isolated environment for learning / demo / PoC.
#  Section 1 of this file is the only place you'll need to add values.
#  Section 2 values do not need to be changed. 
#  Customization is not intended, so has not been fully tested. 
#  If you plan to customize, you'll need Terraform experience.

# ===== Section 1 - Add values here =====
project_id        = ""
svc_instance_name = "" # name of the service instance 
svc_sa            = "" # service instance PSC service attachment
svc_dns_domain    = "" # domain used by the service instance
svc_name          = "" # also becomes host in the service's FQDN


# ===== Section 1.1 - Add values if needed to enable functionality
ext_allowed_ips       = []  # IP(s) allowed in Cloud Armor for external LB, eg ["1.2.3.4/32","5.6.7.8/32"] leave as empty string for no external access. Visit https://whatismyipaddress.com/ or other sites like it to get your public IP address.
psc_sa_num            = "1" # used to quickly change the name of the Southbound PSC Service Attachment
cert_private_key_path = ""  # path and file name of cert private key for load balancers, leave as empty string if not using a cert
cert_path             = ""  # path and file name of cert private key for load balancers, leave as empty string if not using a cert


# ===== Section 2 - No need to change - customize below only if needed (see note above) =====
vpc_infra                     = "vpc-spoke"             # name of VPC where Northbound and Southbound infrastructure will be created, could also be vpc-hub - a VPC name from variables below
subnet_infra                  = "subnet-spoke-us-east1" # name of subnet where Northbound and Southbound infrastructure (for resources the leverage a subnet) - a subnet name from variables below
region_infra                  = "us-east1"              # match this to the region of the subnet named in the variable above, subnet_infra
lb_name                       = "lb-psc-looker-nb"      # becomes the load balancer name for an application load balancer
cert_name_prefix              = "cert"
lb_static_ip_name_prefix      = "static-ip"
cloudarmor_policy_name_prefix = "cldarmr-pol"
health_check_name_prefix      = "hchck"
forwarding_rule_name_prefix   = "fr"
lb_https_proxy_name_prefix    = "proxy-https"
lb_tcp_proxy_name_prefix      = "tcp-proxy"
backend_service_name_prefix   = "bes"
proxy_only_subnet_name        = "proxy-subnet"
proxy_only_subnet_cidr        = "192.168.123.0/24"
cldnat_name                   = "pubnat-gw"

vpn_config = {
  region = "us-east1"
  vpc1   = "vpc-hub"
  #  vpc1-advertised-ranges = ""
  vpc2 = "vpc-dc"
  #  vpc2-advertised-ranges = ""
}

bastion_config = {
  region    = "us-east1"
  zone      = "us-east1-d"
  vm_name   = "windows-srvr-2022-bastion"
  vpc       = "vpc-spoke"
  subnet    = "subnet-spoke-us-east1"
  fw_name   = "allow-iap-rdp-to-bastion"
  fw_ranges = ["35.235.240.0/20"]
}

ghes_config = {
  diskname         = "ghes-disk"
  vpcname          = "vpc-spoke"
  subnetname       = "subnet-spoke-us-east1"
  githubservername = "ghes-vm"
  region           = "us-east1"
  zone             = "us-east1-b"
  #  instancegroupname = "instance-group-1"
}

dc_ghes_config = {
  diskname         = "dc-ghes-disk"
  vpcname          = "vpc-dc"
  subnetname       = "subnet-dc-us-east1"
  githubservername = "dc-ghes-vm"
  region           = "us-east1"
  zone             = "us-east1-b"
  #  instancegroupname = "instance-group-1"
}

psc_sb_infra_config = {
  #  project_id   = "prj-lookercore-network-testing"
  service_type = "inet-neg" # either "inet-neg", "serverless-neg", or "psc-neg"
  # replace all the strings below with one string called service_string and explain what it is
  inet_neg_fqdn_host       = "www"        # leave blank if no Internet NEG
  inet_neg_fqdn_domain     = "github.com" # leave blank if no Internet NEG"
  serverless_instance_name = ""           # leave blank if no serverless NEG
  psc_neg_sa_uri           = ""
  psc_neg_subnet           = "" # for PSC NEG only, can leave blank otherwise
  #  region                         = "us-east1"
  #  vpc                            = "vpc-spoke"
  port = 22
  #  forwarding_rule_subnet         = "subnet-spoke-us-east1"
  service_attachment_nat_iprange = "10.231.0.0/24"
  #  lb_proxy_only_subnet           = "192.168.123.0/24"
}

# VPCs / subnets config
spoke_network = "vpc-spoke"
spoke_subnets = [
  {
    name               = "subnet-spoke-us-central1"
    ip_cidr_range      = "10.100.1.0/24"
    region             = "us-central1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  },
  {
    name               = "subnet-spoke-us-east1"
    ip_cidr_range      = "10.101.1.0/24"
    region             = "us-east1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
]

hub_network = "vpc-hub"
hub_subnets = [
  {
    name               = "subnet-hub-us-central1"
    ip_cidr_range      = "10.10.1.0/24"
    region             = "us-central1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  },
  {
    name               = "subnet-hub-us-east1"
    ip_cidr_range      = "10.11.1.0/24"
    region             = "us-east1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
]

dc_network = "vpc-dc"
dc_subnets = [
  {
    name               = "subnet-dc-us-central1"
    ip_cidr_range      = "172.16.1.0/24"
    region             = "us-central1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  },
  {
    name               = "subnet-dc-us-east1"
    ip_cidr_range      = "172.17.1.0/24"
    region             = "us-east1"
    secondary_ip_range = null
    flow_logs_config = {
      flow_sampling        = 1.0
      aggregation_interval = "INTERVAL_5_SEC"
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
]

# ===== APIs and org policies
services = ["compute.googleapis.com",
  "certificatemanager.googleapis.com",
"dns.googleapis.com"]

# org policies to not enforced in the project - enforced / not enforced type policies
boolorgpols = ["requireShieldedVm", "disableInternetNetworkEndpointGroup"]

# org policies to allow all in the project - allow all / deny all type org policies
listorgpols = ["trustedImageProjects", "restrictVpnPeerIPs"] 