/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

variable "project_id" {
  description = "Project id"
  type        = string
}

variable "looker_project_id" {
  type = string
}

variable "psc_sa_num" {
  type = string
}

variable "svc_name" {
  type = string
}

variable "svc_dns_domain" {
  type = string
}

variable "psc_sb_infra_config" {
  description = ""
  type = object({
    service_type                   = string
    inet_neg_fqdn_host             = string
    inet_neg_fqdn_domain           = string
    serverless_instance_name       = string
    psc_neg_sa_uri                 = string
    psc_neg_subnet                 = string
    port                           = string
    service_attachment_nat_iprange = string
  })
}

# ===== Northbound LB & associated resources =====

variable "svc_sa" {
  description = "PSC Service Attachment target for PSC NEG"
  type        = string
}

variable "vpc_infra" {
  type = string
}

variable "subnet_infra" {
  type = string
}

variable "region_infra" {
  type = string
}

variable "lb_name" {
  type = string
}

variable "lb_tcp_proxy_name_prefix" {
  type = string
}

variable "ext_allowed_ips" {
  type = list(string)
}

variable "svc_instance_name" {
  description = "name of the Looker instance to update the VPCs that allowed to reach it via PSC"
  type        = string
}

variable "cert_private_key_path" {
  type = string
}

variable "cert_path" {
  type = string
}

variable "cert_name_prefix" {
  type    = string
  default = "cert"
}

variable "lb_static_ip_name_prefix" {
  type    = string
  default = "reserved-ip"
}

variable "cloudarmor_policy_name_prefix" {
  type    = string
  default = "cldarmr-pol"
}

variable "health_check_name_prefix" {
  type    = string
  default = "hchck"
}

variable "forwarding_rule_name_prefix" {
  type    = string
  default = "fr"
}

variable "lb_https_proxy_name_prefix" {
  type    = string
  default = "proxy-http"
}

variable "backend_service_name_prefix" {
  type    = string
  default = "bes"
}


# ===== VPCs, subnets and VMs =====

variable "proxy_only_subnet_name" {
  type = string
}

variable "proxy_only_subnet_cidr" {
  type = string
}

variable "create_vpcs" {
  description = "if VPCs already created (existing environment), set to false"
  type        = bool
  default     = true
}

variable "spoke_network" {
  description = "VPC name"
  type        = string
}

variable "spoke_subnets" {
  description = "Subnets"
  #  type = list(object({
  type = object({
    name               = string
    ip_cidr_range      = string
    region             = optional(string, "")
    secondary_ip_range = map(string)
    flow_logs_config = object({
      aggregation_interval = string
      flow_sampling        = number
      metadata             = string
    })
  })
  #  }))
}

variable "hub_network" {
  description = "VPC name"
  type        = string
}

variable "hub_subnets" {
  description = "Subnets"
  #  type = list(object({
  type = object({
    name               = string
    ip_cidr_range      = string
    region             = optional(string, "")
    secondary_ip_range = map(string)
    flow_logs_config = object({
      aggregation_interval = string
      flow_sampling        = number
      metadata             = string
    })
  })
  #  }))
}

variable "dc_network" {
  description = "VPC name"
  type        = string
}

variable "dc_subnets" {
  description = "Subnets"
  #  type = list(object({
  type = object({
    name               = string
    ip_cidr_range      = string
    region             = optional(string, "")
    secondary_ip_range = map(string)
    flow_logs_config = object({
      aggregation_interval = string
      flow_sampling        = number
      metadata             = string
    })
  })
  #  }))
}

variable "create_looker" {
  description = "if Looker already created (existing environment), set to false"
  type        = bool
  default     = false
}

variable "vm_zone_suffix" {
  description = "zone suffix, eg -c, to add to the end of the region_infra value"
  type        = string
}

variable "ghes_config" {
  description = "Settings for the GitHub Enterprise Server"
  type = object({
    diskname         = string
    vpcname          = string
    subnetname       = string
    githubservername = string
    region           = optional(string, "")
    zone             = optional(string, "")
    #    instancegroupname = string    
  })
}

variable "dc_ghes_config" {
  description = "Settings for the GitHub Enterprise Server"
  type = object({
    diskname         = string
    vpcname          = string
    subnetname       = string
    githubservername = string
    region           = optional(string, "")
    zone             = optional(string, "")
    #    instancegroupname = string    
  })
}

variable "cldnat_name" {
  type = string
}

variable "vpn_config" {
  type = object({
    region                 = optional(string, "")
    vpc1                   = string
    vpc1-advertised-ranges = optional(map(string), {})
    vpc2                   = string
    vpc2-advertised-ranges = optional(map(string), {})
  })
}

variable "bastion_config" {
  description = "Settings for bastion host"
  type = object({
    region    = optional(string, "")
    zone      = optional(string, "")
    vm_name   = string
    vpc       = string
    subnet    = string
    fw_name   = string
    fw_ranges = list(string)
  })
}

# ===== APIs and org policies =====

variable "services" {
  description = "APIs to enable"
  type        = list(string)
}

# enforced / not enforced type policies
variable "boolorgpols" {
  description = "APIs to enable"
  type        = list(string)
}

# allow all / deny all type org policies
variable "listorgpols" {
  description = "APIs to enable"
  type        = list(string)
}
