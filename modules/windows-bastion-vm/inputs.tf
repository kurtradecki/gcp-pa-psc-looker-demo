variable "project_id" {
  description = "Project id"
  type        = string
}

variable "bastion_config" {
  description = "Settings for the GitHub Enterprise Server"
  type = object({
    region    = string
    zone      = string
    vm_name   = string
    vpc       = string
    subnet    = string
    fw_name   = string
    fw_ranges = list(string)
  })
}