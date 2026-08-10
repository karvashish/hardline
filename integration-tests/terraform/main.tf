locals {
  instance_id = lower(substr(var.instance_name_prefix, 0, 63))
  network_tag = lower(substr("${var.instance_name_prefix}-ssh", 0, 63))

  labels = merge(
    {
      owner      = "hardline-itest"
      managed_by = "terraform"
    },
    var.additional_labels,
  )

  ssh_pub_key = trimspace(file(var.ssh_public_key_path))
}

locals {
  os_images = {
    ubuntu = { family = "ubuntu-2404-lts-amd64", project = "ubuntu-os-cloud" }
    rocky  = { family = "rocky-linux-9", project = "rocky-linux-cloud" }
    # The published Fedora families carry an arch suffix, so the name is not
    # just the release number.
    fedora = { family = "fedora-cloud-44-x86-64", project = "fedora-cloud" }
  }

  # dnf needs more memory than apt to resolve a transaction; e2-micro OOMs.
  os_machine_type = var.os == "ubuntu" ? var.machine_type : "e2-medium"

  os_bootstrap = var.os == "ubuntu" ? "export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y openssh-server sudo nftables" : "dnf -y install openssh-server sudo nftables"

  # Debian-family puts the admin group at "sudo", RHEL-family at "wheel".
  os_admin_group = var.os == "ubuntu" ? "sudo" : "wheel"
}

data "google_compute_image" "target" {
  family  = local.os_images[var.os].family
  project = local.os_images[var.os].project
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
  machine_type = local.os_machine_type
  tags         = [local.network_tag]
  labels       = local.labels

  can_ip_forward            = false
  deletion_protection       = false
  allow_stopping_for_update = true

  boot_disk {
    auto_delete = true
    initialize_params {
      image = data.google_compute_image.target.self_link
      # GCE rejects a boot disk smaller than the image it is created from, and
      # the RHEL-family images are 20 GB against Ubuntu's 10. Take the image's
      # own size as the floor so the default fits whichever target is selected.
      size = max(var.boot_disk_size_gb, data.google_compute_image.target.disk_size_gb)
      type = var.boot_disk_type
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
    ${local.os_bootstrap}
    id -u ${var.ssh_user} >/dev/null 2>&1 || useradd -m -s /bin/bash ${var.ssh_user}
    usermod -aG ${local.os_admin_group} ${var.ssh_user}
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
