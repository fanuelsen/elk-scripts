# ELK Stack Deployment Scripts

Automated deployment scripts for Elasticsearch, Kibana, and Fleet Server with Docker.

## 📋 Overview

This repository contains two scripts for deploying a complete ELK stack:

1. **`debian13-elk-docker.sh`** - Proxmox VE script that creates a Debian 13 VM with Docker + ELK stack
2. **`elk-docker-install.sh`** - Generic installer for any existing Debian-based Linux system

## 🚀 Quick Start

### Option 1: Proxmox VE (New VM)

```bash
# Run on your Proxmox host to create a complete ELK VM
bash debian13-elk-docker.sh
```

This creates a ready-to-use VM with everything pre-installed.

### Option 2: Existing Debian/Ubuntu System

```bash
# Run on any existing Debian-based system
sudo bash elk-docker-install.sh
```

This installs Docker + ELK stack on your current system.

## 📦 Script 1: Proxmox VE Installer (`debian13-elk-docker.sh`)

Creates a complete Debian 13 VM in Proxmox with Docker and full ELK stack pre-configured.

### Features

- ✅ **Complete automation** - One command creates everything
- ✅ **Optimized VM** - 50GB disk, 8GB RAM, 4 CPU cores (customizable)
- ✅ **Host CPU passthrough** - Required for Elasticsearch 9.2+ (x86-64-v2)
- ✅ **3-node Elasticsearch cluster** - Production-ready with SSL/TLS
- ✅ **Kibana dashboard** - Pre-configured and ready
- ✅ **Fleet Server** - Auto-enrolled on first boot
- ✅ **Docker security** - userns-remap enabled
- ✅ **Auto-start services** - Systemd services for ELK and Fleet

### Prerequisites

- Proxmox VE 8.x or 9.0
- AMD64 architecture
- Internet connection
- libguestfs-tools (auto-installed if missing)

### Usage

```bash
# Download and run on Proxmox host
wget https://raw.githubusercontent.com/yourusername/elk-scripts/main/debian13-elk-docker.sh
bash debian13-elk-docker.sh
```

### VM Specifications

| Resource | Default | Minimum | Recommended |
|----------|---------|---------|-------------|
| RAM      | 8192MB  | 4096MB  | 8192MB+     |
| Disk     | 50GB    | 30GB    | 50GB+       |
| CPU      | 4 cores | 2 cores | 4+ cores    |
| CPU Type | Host    | Host    | Host (required) |

### What Gets Created

The script creates a VM with:
- Debian 13 (latest cloud image)
- Docker CE with userns-remap security
- 3-node Elasticsearch cluster (v9.2.0)
- Kibana (v9.2.0)
- Fleet Server (auto-configured on first boot)
- User: `debian` / `debian` (passwordless sudo)
- Root password: randomly generated (shown after creation)

### Post-Creation

After the VM is created:

1. **Start the VM** (if you didn't auto-start it)
2. **Wait 2-5 minutes** for first boot services to initialize
3. **Get the VM IP**: Check Proxmox console or use `qm guest cmd VMID network-get-interfaces`
4. **Access Kibana**: `http://VM_IP:5601`

Credentials are saved in `/docker/elk/.env` on the VM.

## 🐘 Script 2: Generic Installer (`elk-docker-install.sh`)

Installs Docker and full ELK stack on any existing Debian-based Linux system.

### Features

- ✅ **Universal compatibility** - Works on Debian, Ubuntu, Mint, Pop!_OS, etc.
- ✅ **Complete automation** - No manual steps required
- ✅ **3-node Elasticsearch cluster** - Production-ready with SSL/TLS
- ✅ **Kibana + Fleet Server** - Fully configured and integrated
- ✅ **Health monitoring** - Waits for services to be ready
- ✅ **Time sync verification** - Prevents certificate issues
- ✅ **Systemd integration** - Auto-start on boot
- ✅ **Docker security** - userns-remap enabled

### Prerequisites

- Debian-based Linux (Debian 11+, Ubuntu 20.04+, Mint, Pop!_OS, etc.)
- AMD64 architecture
- Minimum 4GB RAM (8GB+ recommended)
- Minimum 30GB free disk space
- Internet connection
- Root or sudo access

### Usage

```bash
# Download and run
wget https://raw.githubusercontent.com/yourusername/elk-scripts/main/elk-docker-install.sh
sudo bash elk-docker-install.sh

# Or if you cloned the repo
cd elk-scripts
sudo bash elk-docker-install.sh
```

### Installation Process

The script automatically:

1. ✅ Checks system compatibility (OS, RAM, disk, architecture)
2. ✅ Verifies time synchronization
3. ✅ Installs Docker CE with compose plugin
4. ✅ Configures Docker with userns-remap security
5. ✅ Sets kernel parameters (vm.max_map_count)
6. ✅ Creates ELK configuration in `/opt/elk`
7. ✅ Generates secure random passwords
8. ✅ Starts Elasticsearch cluster and waits for health
9. ✅ Starts Kibana and waits for readiness
10. ✅ Configures Fleet Server with auto-enrollment
11. ✅ Creates systemd service for auto-start

### Post-Installation

After successful installation:

```
═══════════════════════════════════════════════════════════
  ✅ Elasticsearch Stack Installation Complete!
═══════════════════════════════════════════════════════════
  🐋 Docker:       Installed with userns-remap
  🔍 Elasticsearch: 3-node cluster
  📊 Kibana:       Installed
  🚀 Fleet Server: Installed and running
  ▶️  Status:       Running

  Elasticsearch Credentials:
    • Elastic user: elastic
    • Elastic pass: [randomly generated]
    • Kibana user:  kibana_system
    • Kibana pass:  [randomly generated]

  Access URLs:
    • Elasticsearch: https://YOUR_IP:9200
    • Kibana:        http://YOUR_IP:5601
    • Fleet Server:  https://YOUR_IP:8220
```

**⚠️ SAVE THESE CREDENTIALS!** They are also stored in `/opt/elk/.env`

## 🔑 Default Access

### Proxmox Script VM (`debian13-elk-docker.sh`)

| Service       | URL/Access           | Username        | Password              | Location          |
|---------------|----------------------|-----------------|----------------------|-------------------|
| VM SSH        | VM_IP:22             | debian          | debian               | -                 |
| VM Root       | VM_IP:22             | root            | (random, displayed)  | -                 |
| Elasticsearch | https://VM_IP:9200   | elastic         | (random)             | /docker/elk/.env  |
| Kibana        | http://VM_IP:5601    | elastic         | (random)             | /docker/elk/.env  |
| Fleet Server  | https://VM_IP:8220   | -               | -                    | /docker/elk/.env  |

Files on VM: `/docker/elk/`

### Generic Script (`elk-docker-install.sh`)

| Service       | URL                  | Username        | Password              | Location         |
|---------------|----------------------|-----------------|----------------------|------------------|
| Elasticsearch | https://localhost:9200 | elastic       | (random)             | /opt/elk/.env    |
| Kibana        | http://localhost:5601  | elastic       | (random)             | /opt/elk/.env    |
| Fleet Server  | https://localhost:8220 | -             | -                    | /opt/elk/.env    |

Files on system: `/opt/elk/`

## 📊 Components Installed

| Component         | Version | Port | Description                    |
|-------------------|---------|------|--------------------------------|
| Docker CE         | Latest  | -    | Container runtime              |
| Elasticsearch     | 9.2.0   | 9200 | 3-node cluster (es01, es02, es03) |
| Kibana            | 9.2.0   | 5601 | Analytics and visualization    |
| Fleet Server      | 9.2.0   | 8220 | Elastic Agent management       |

## 🛠️ Management

### Docker Compose

```bash
# Proxmox VM
cd /docker/elk

# Generic install
cd /opt/elk

# View status
docker compose ps

# View logs
docker compose logs -f

# Restart all
docker compose restart

# Stop all
docker compose down

# Start all
docker compose up -d
```

### Systemd

```bash
# Start/stop/restart
sudo systemctl start elk-stack
sudo systemctl stop elk-stack
sudo systemctl restart elk-stack

# Check status
sudo systemctl status elk-stack
```

### Health Checks

```bash
# Elasticsearch cluster health
curl -u elastic:PASSWORD -k https://localhost:9200/_cluster/health?pretty

# Kibana status
curl http://localhost:5601/api/status

# Fleet Server status
curl -k https://localhost:8220/api/status
```

## 🔐 Security

### Implemented Security

- ✅ **Docker userns-remap** - Container user namespace remapping
- ✅ **SSL/TLS encryption** - All Elasticsearch inter-node communication
- ✅ **Self-signed certificates** - Auto-generated CA and node certs
- ✅ **Strong passwords** - 16-character random passwords
- ✅ **Network isolation** - Docker network segmentation

### Recommended Additional Steps

```bash
# Change default debian user password (Proxmox VM)
passwd

# Configure firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5601/tcp  # Kibana
sudo ufw allow 9200/tcp  # Elasticsearch
sudo ufw allow 8220/tcp  # Fleet Server
sudo ufw enable
```

## 🐛 Troubleshooting

### Certificate Errors

```bash
# Usually caused by time sync issues
timedatectl status

# Fix time sync
sudo timedatectl set-ntp true

# Regenerate certificates
cd /opt/elk  # or /docker/elk on Proxmox VM
docker compose down
docker volume rm elk_certs
docker compose up -d
```

### Elasticsearch Won't Start

```bash
# Check vm.max_map_count
sysctl vm.max_map_count
# Should be 262144

# Set if needed
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Out of Memory

```bash
# Check usage
free -h
docker stats

# Reduce memory per service (edit MEM_LIMIT)
nano /opt/elk/.env  # or /docker/elk/.env
# Change MEM_LIMIT from 2147483648 to 1073741824 (1GB)

# Restart
docker compose restart
```

### Container Not Starting

```bash
# Check logs
docker compose logs [container-name]

# Common issues:
# - Port already in use: Check with `netstat -tulpn`
# - Out of disk: Check with `df -h`
# - Time sync: Run `timedatectl set-ntp true`
```

## 📁 File Locations

### Proxmox VM (`debian13-elk-docker.sh`)

| Path | Description |
|------|-------------|
| `/docker/elk/` | Main directory |
| `/docker/elk/docker-compose.yml` | Service definitions |
| `/docker/elk/.env` | Credentials and config |
| `/docker/elk/setup-fleet.sh` | Fleet setup script |
| `/var/lib/elk/` | State files |

### Generic Install (`elk-docker-install.sh`)

| Path | Description |
|------|-------------|
| `/opt/elk/` | Main directory |
| `/opt/elk/docker-compose.yml` | Service definitions |
| `/opt/elk/.env` | Credentials and config |
| `/opt/elk/setup-fleet.sh` | Fleet setup script |
| `/etc/systemd/system/elk-stack.service` | Systemd service |
| `/etc/sysctl.d/99-elasticsearch.conf` | Kernel parameters |

## 💾 System Requirements

### Minimum

- **RAM:** 4GB
- **Disk:** 30GB free
- **CPU:** 2 cores
- **Architecture:** AMD64

### Recommended

- **RAM:** 8GB+
- **Disk:** 50GB+
- **CPU:** 4+ cores
- **Network:** 1Gbps

### Typical Resource Usage

```
Service         CPU      Memory
es01            5-15%    1.5-2GB
es02            5-15%    1.5-2GB
es03            5-15%    1.5-2GB
kibana          1-5%     500MB-1GB
fleet-server    1-3%     200-500MB
```

## 🔄 Upgrading

```bash
# Change version in .env
nano /opt/elk/.env  # or /docker/elk/.env

# Update STACK_VERSION to desired version
STACK_VERSION=9.3.0

# Pull new images and restart
docker compose pull
docker compose up -d
```

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a pull request.

## 📝 License

MIT License

## ⚠️ Disclaimer

These scripts are provided as-is. Always review scripts before running with root privileges. Test in non-production environments first.

## 📚 Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Fleet Documentation](https://www.elastic.co/guide/en/fleet/current/index.html)
- [Docker Documentation](https://docs.docker.com/)
- [Proxmox Documentation](https://pve.proxmox.com/pve-docs/)

---

**Built for easy ELK stack deployment**
