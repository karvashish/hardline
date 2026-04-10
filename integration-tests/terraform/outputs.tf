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

output "ssh_private_key_path_hint" {
  description = "Absolute SSH private key path used for human and itest commands."
  value       = var.ssh_private_key_path_hint
}

output "labels" {
  description = "Applied labels."
  value       = google_compute_instance.itest_vm.labels
}

output "ssh_command" {
  description = "Convenience SSH command."
  value       = format("ssh -i %s %s@%s", var.ssh_private_key_path_hint, var.ssh_user, google_compute_instance.itest_vm.network_interface[0].access_config[0].nat_ip)
}
