# -*- mode: ruby -*-
# Mirage honeynet VM.
#   NIC1  NAT                 - vagrant ssh + apt/docker pulls (host egress only)
#   NIC2  host-only  .56.10   - management: real sshd, Kibana, correlator UI
#   NIC3  intnet "honeynet"   - traps on 10.66.0.10/.20/.30 (configured by ansible)

HONEYNET_MAC = "0800276A0010" # fixed so netplan can match it

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"
  config.vm.hostname = "mirage"
  config.vm.boot_timeout = 600

  config.vm.network "private_network", ip: "192.168.56.10"
  config.vm.network "private_network", virtualbox__intnet: "honeynet",
    mac: HONEYNET_MAC, auto_config: false

  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provider "virtualbox" do |vb|
    vb.name = "mirage-honeynet"
    vb.memory = 8192
    vb.cpus = 4
    vb.gui = false
    # Suricata sniffs the honeynet NIC
    vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
  end

  # Ubuntu's own ansible-core is enough; skip Vagrant's PPA-based installer
  config.vm.provision "bootstrap", type: "shell", inline: <<-SHELL
    if ! command -v ansible-playbook >/dev/null; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -q
      apt-get install -yq ansible-core python3-debian
    fi
  SHELL

  config.vm.provision "ansible", type: "ansible_local" do |ansible|
    ansible.install = false
    ansible.provisioning_path = "/vagrant/provision/ansible"
    ansible.playbook = "site.yml"
    ansible.compatibility_mode = "2.0"
  end
end
