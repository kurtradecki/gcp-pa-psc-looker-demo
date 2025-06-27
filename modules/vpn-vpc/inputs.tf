variable "project_id" {
  description = "Project id"
  type        = string
}

variable "vpn_config" {
  type = object({
    region = string
    vpc1   = string
    vpc1-advertised-ranges = optional(map(string),{})
    vpc2 = string
    vpc2-advertised-ranges = optional(map(string),{})
  })
}