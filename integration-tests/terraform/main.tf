locals {
  run_id      = random_id.run_id.hex
  instance_id = lower(substr("${var.instance_name_prefix}-${local.run_id}", 0, 63))
  network_tag = lower(substr("hardline-itest-${local.run_id}", 0, 63))
  expires_at  = formatdate("YYYYMMDDhhmm", time_offset.expires.rfc3339)

  labels = merge(
    {
      owner      = "hardline-itest"
      managed_by = "terraform"
      run_id     = local.run_id
      expires_at = local.expires_at
    },
    var.additional_labels,
  )

  ssh_pub_key = trimspace(file(var.ssh_public_key_path))
}

resource "random_id" "run_id" {
  byte_length = 4
}

resource "time_static" "created_at" {}

resource "time_offset" "expires" {
  base_rfc3339 = time_static.created_at.rfc3339
  offset_hours = var.max_lifetime_hours
}

data "google_compute_image" "ubuntu_2404" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

resource "google_compute_firewall" "ssh" {
  count   = var.create_ssh_firewall_rule ? 1 : 0
  name    = lower(substr("${local.instance_id}-ssh", 0, 63))
  network = var.network

  description = "Ephemeral SSH ingress for hardline integration VM."
  direction   = "INGRESS"
  priority    = 1000

  target_tags   = [local.network_tag]
  source_ranges = var.allowed_ssh_cidrs

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance" "itest_vm" {
  name         = local.instance_id
  zone         = var.zone
  machine_type = var.machine_type
  tags         = [local.network_tag]
  labels       = local.labels

  can_ip_forward            = false
  deletion_protection       = false
  allow_stopping_for_update = true

  boot_disk {
    auto_delete = true
    initialize_params {
      image = data.google_compute_image.ubuntu_2404.self_link
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
    access_config {}
  }

  metadata = {
    "enable-oslogin" = "FALSE"
    "ssh-keys"       = "${var.ssh_user}:${local.ssh_pub_key}"
  }

  metadata_startup_script = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y openssh-server sudo nftables
    id -u ${var.ssh_user} >/dev/null 2>&1 || useradd -m -s /bin/bash ${var.ssh_user}
    usermod -aG sudo ${var.ssh_user}
    install -d -m 700 -o ${var.ssh_user} -g ${var.ssh_user} /home/${var.ssh_user}/.ssh
    touch /home/${var.ssh_user}/.ssh/authorized_keys
    grep -qxF '${local.ssh_pub_key}' /home/${var.ssh_user}/.ssh/authorized_keys || echo '${local.ssh_pub_key}' >> /home/${var.ssh_user}/.ssh/authorized_keys
    chown ${var.ssh_user}:${var.ssh_user} /home/${var.ssh_user}/.ssh/authorized_keys
    chmod 600 /home/${var.ssh_user}/.ssh/authorized_keys
    systemctl enable ssh || systemctl enable sshd || true
    systemctl restart ssh || systemctl restart sshd || true
  EOT

  dynamic "scheduling" {
    for_each = var.use_spot ? [1] : []
    content {
      automatic_restart   = false
      preemptible         = true
      provisioning_model  = "SPOT"
      on_host_maintenance = "TERMINATE"
    }
  }
}
