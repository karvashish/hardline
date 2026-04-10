variable "project_id" {
  description = "GCP project ID used for integration test instances."
  type        = string
}

variable "expected_gcloud_account" {
  description = "Expected active gcloud account (used by local preflight checks)."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone."
  type        = string
  default     = "us-central1-a"
}

variable "instance_name_prefix" {
  description = "Prefix for ephemeral integration VM names."
  type        = string
  default     = "hardline-itest"
}

variable "machine_type" {
  description = "GCE machine type for the integration VM."
  type        = string
  default     = "e2-micro"
}

variable "boot_disk_type" {
  description = "Boot disk type."
  type        = string
  default     = "pd-balanced"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB."
  type        = number
  default     = 10

  validation {
    condition     = var.boot_disk_size_gb >= 10
    error_message = "boot_disk_size_gb must be at least 10 GB."
  }
}

variable "network" {
  description = "VPC network name (self link also accepted)."
  type        = string
  default     = "default"
}

variable "subnetwork" {
  description = "Optional subnetwork name/self link."
  type        = string
  default     = null
}

variable "create_ssh_firewall_rule" {
  description = "Create a scoped SSH ingress rule for this instance."
  type        = bool
  default     = true
}

variable "allowed_ssh_cidrs" {
  description = "CIDR ranges allowed to SSH to this integration VM."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ssh_user" {
  description = "SSH username used by integration tests."
  type        = string
  default     = "hardline"
}

variable "ssh_public_key_path" {
  description = "Absolute path to public SSH key injected into VM metadata."
  type        = string
}

variable "use_spot" {
  description = "Use spot/preemptible VM to reduce costs (less reliable)."
  type        = bool
  default     = false
}

variable "additional_labels" {
  description = "Additional labels to add to the integration VM."
  type        = map(string)
  default     = {}
}

variable "ssh_private_key_path_hint" {
  description = "Absolute SSH private key path used by itest and ssh command output."
  type        = string
  default     = "/home/REPLACE_ME/.ssh/id_ed25519"
}
