variable "project_id" {
  description = "Project id"
  type        = string
}

variable "ghes_config" {
  description = "Settings for the GitHub Enterprise Server"
  type = object({
    diskname         = string
    vpcname          = string
    subnetname       = string
    githubservername = string
    region           = string
    zone             = string
    #    instancegroupname = string    
  })
}