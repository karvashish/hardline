output "instance_name" {
  description = "Ephemeral integration VM name."
  value       = google_compute_instance.itest_vm.name
}

output "project_id" {
  description = "GCP project ID."
  value       = var.project_id
}

output "zone" {
  description = "GCP zone."
  value       = var.zone
}

output "external_ip" {
  description = "Public IP for SSH."
  value       = google_compute_instance.itest_vm.network_interface[0].access_config[0].nat_ip
}

output "ssh_user" {
  description = "SSH username."
  value       = var.ssh_user
}

output "expires_at" {
  description = "Label value used for janitor cleanup."
  value       = local.expires_at
}

output "labels" {
  description = "Applied labels."
  value       = google_compute_instance.itest_vm.labels
}

output "run_id" {
  description = "Randomized run identifier."
  value       = local.run_id
}

output "ssh_command" {
  description = "Convenience SSH command."
  value       = format("ssh -i %s %s@%s", var.ssh_private_key_path_hint, var.ssh_user, google_compute_instance.itest_vm.network_interface[0].access_config[0].nat_ip)
}
