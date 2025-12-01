#!/usr/bin/env bash

# Minimal Debian 13 Server with Docker + Elasticsearch Stack
# Based on community-scripts but optimized for ELK stack deployment
# License: MIT

source /dev/stdin <<<$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/api.func)

function header_info {
  clear
  cat <<"EOF"
    ____       __    _                ________   ________    __ __
   / __ \___  / /_  (_)___ _____     <  /__  /  / ____/ /   / //_/
  / / / / _ \/ __ \/ / __ `/ __ \    / / /_ <  / __/ / /   / ,<
 / /_/ /  __/ /_/ / / /_/ / / / /   / /___/ / / /___/ /___/ /| |
/_____/\___/_.___/_/\__,_/_/ /_/   /_//____/ /_____/_____/_/ |_|

           DEBIAN 13 + DOCKER + ELASTICSEARCH STACK
EOF
}
header_info
echo -e "\n Loading..."

# Generate unique identifiers
GEN_MAC=02:$(openssl rand -hex 5 | awk '{print toupper($0)}' | sed 's/\(..\)/\1:/g; s/.$//')
RANDOM_UUID="$(cat /proc/sys/kernel/random/uuid)"
NSAPP="debian13-elk-docker"
var_os="debian"
var_version="13"

# Color codes
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")

# Error handling
set -e
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR
trap cleanup EXIT
trap 'post_update_to_api "failed" "INTERRUPTED"' SIGINT
trap 'post_update_to_api "failed" "TERMINATED"' SIGTERM

function error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  local error_message="${RD}[ERROR]${CL} in line ${RD}$line_number${CL}: exit code ${RD}$exit_code${CL}: while executing command ${YW}$command${CL}"
  post_update_to_api "failed" "${command}"
  echo -e "\n$error_message\n"
  cleanup_vmid
}

function get_valid_nextid() {
  local try_id
  try_id=$(pvesh get /cluster/nextid)
  while true; do
    if [ -f "/etc/pve/qemu-server/${try_id}.conf" ] || [ -f "/etc/pve/lxc/${try_id}.conf" ]; then
      try_id=$((try_id + 1))
      continue
    fi
    if lvs --noheadings -o lv_name 2>/dev/null | grep -qE "(^|[-_])${try_id}($|[-_])"; then
      try_id=$((try_id + 1))
      continue
    fi
    break
  done
  echo "$try_id"
}

function cleanup_vmid() {
  if qm status $VMID &>/dev/null; then
    qm stop $VMID &>/dev/null
    qm destroy $VMID &>/dev/null
  fi
}

function cleanup() {
  popd >/dev/null
  post_update_to_api "done" "none"
  rm -rf $TEMP_DIR
}

TEMP_DIR=$(mktemp -d)
pushd $TEMP_DIR >/dev/null

function msg_info() {
  local msg="$1"
  echo -ne "  ${YW}${msg}${CL}"
}

function msg_ok() {
  local msg="$1"
  echo -e "\r\033[K  ✅ ${GN}${msg}${CL}"
}

function msg_error() {
  local msg="$1"
  echo -e "\r\033[K  ❌ ${RD}${msg}${CL}"
}

function check_root() {
  if [[ "$(id -u)" -ne 0 || $(ps -o comm= -p $PPID) == "sudo" ]]; then
    clear
    msg_error "Please run this script as root."
    echo -e "\nExiting..."
    sleep 2
    exit
  fi
}

function pve_check() {
  local PVE_VER
  PVE_VER="$(pveversion | awk -F'/' '{print $2}' | awk -F'-' '{print $1}')"

  if [[ "$PVE_VER" =~ ^8\.([0-9]+) ]]; then
    local MINOR="${BASH_REMATCH[1]}"
    if ((MINOR < 0 || MINOR > 9)); then
      msg_error "This version of Proxmox VE is not supported."
      msg_error "Supported: Proxmox VE version 8.0 – 8.9"
      exit 1
    fi
    return 0
  fi

  if [[ "$PVE_VER" =~ ^9\.([0-9]+) ]]; then
    local MINOR="${BASH_REMATCH[1]}"
    if ((MINOR != 0)); then
      msg_error "This version of Proxmox VE is not yet supported."
      msg_error "Supported: Proxmox VE version 9.0"
      exit 1
    fi
    return 0
  fi

  msg_error "This version of Proxmox VE is not supported."
  msg_error "Supported versions: Proxmox VE 8.0 – 8.x or 9.0"
  exit 1
}

function arch_check() {
  if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    echo -e "\n  ${YW}This script will not work with PiMox! \n"
    echo -e "Exiting..."
    sleep 2
    exit
  fi
}

# Generate random passwords (16 characters for security)
ELASTIC_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
KIBANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
# Generate random 32 hex character encryption key for Kibana
KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 16)

# Settings optimized for ELK stack
VMID=$(get_valid_nextid)
FORMAT=",efitype=4m"
MACHINE=""
DISK_SIZE="50G"       # 50GB for Elasticsearch data
DISK_CACHE=""
HN="elk-docker"
CPU_TYPE=" -cpu host" # Host CPU required for x86-64-v2 (Elasticsearch 9.2+)
CORE_COUNT="4"        # 4 cores for ELK stack
RAM_SIZE="8192"       # 8GB RAM for Elasticsearch
BRG="vmbr0"
MAC="$GEN_MAC"
VLAN=""
MTU=""
START_VM="no"

echo -e "\n${BGN}═══════════════════════════════════════════════════════════${CL}"
echo -e "${BGN}  Debian 13 + Docker + Elasticsearch Stack${CL}"
echo -e "${BGN}═══════════════════════════════════════════════════════════${CL}"
echo -e "  🆔 VM ID:        ${BL}${VMID}${CL}"
echo -e "  💾 Disk Size:    ${BL}${DISK_SIZE}${CL}"
echo -e "  🧠 CPU Cores:    ${BL}${CORE_COUNT}${CL}"
echo -e "  ⚙️  CPU Type:     ${BL}Host (x86-64-v2 for ES 9.2+)${CL}"
echo -e "  🛠️  RAM:          ${BL}${RAM_SIZE}MB${CL}"
echo -e "  🏠 Hostname:     ${BL}${HN}${CL}"
echo -e "  🌉 Bridge:       ${BL}${BRG}${CL}"
echo -e "  🔗 MAC:          ${BL}${MAC}${CL}"
echo -e "  🏷️  VLAN:         ${BL}Default (none)${CL}"
echo -e "  🐋 Docker:       ${BL}Latest with userns-remap${CL}"
echo -e "  🔍 Elasticsearch:${GN}3-node cluster + Kibana${CL}"
echo -e "${BGN}═══════════════════════════════════════════════════════════${CL}\n"

if (whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --title "CONFIRM INSTALLATION" --yesno "Create Debian 13 + Docker + ELK stack with the above settings?\n\nNote: This will deploy a 3-node Elasticsearch cluster with Kibana." 14 75); then
  :
else
  clear
  echo -e "  ${RD}Installation cancelled${CL}\n"
  exit
fi

# Optional: Allow basic customization
if (whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --title "CUSTOMIZE" --yesno "Would you like to customize RAM, disk size, and VLAN?" --defaultno 10 60); then

  if RAM_SIZE=$(whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --inputbox "RAM in MB (minimum 4096, recommended 8192+)" 8 60 8192 --title "RAM SIZE" 3>&1 1>&2 2>&3); then
    if [[ "$RAM_SIZE" =~ ^[0-9]+$ ]] && [ "$RAM_SIZE" -ge 4096 ]; then
      echo -e "  RAM set to: ${BL}${RAM_SIZE}MB${CL}"
    else
      RAM_SIZE="8192"
      echo -e "  Invalid input, using default: ${BL}8192MB${CL}"
    fi
  fi

  if DISK_SIZE=$(whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --inputbox "Disk size in GB (minimum 30, recommended 50+)" 8 60 50 --title "DISK SIZE" 3>&1 1>&2 2>&3); then
    if [[ "$DISK_SIZE" =~ ^[0-9]+$ ]] && [ "$DISK_SIZE" -ge 30 ]; then
      DISK_SIZE="${DISK_SIZE}G"
      echo -e "  Disk size set to: ${BL}${DISK_SIZE}${CL}"
    else
      DISK_SIZE="50G"
      echo -e "  Invalid input, using default: ${BL}50G${CL}"
    fi
  fi

  if VLAN_INPUT=$(whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --inputbox "VLAN tag (leave empty for no VLAN)" 8 60 --title "VLAN TAG" 3>&1 1>&2 2>&3); then
    if [ -n "$VLAN_INPUT" ] && [[ "$VLAN_INPUT" =~ ^[0-9]+$ ]] && [ "$VLAN_INPUT" -ge 1 ] && [ "$VLAN_INPUT" -le 4094 ]; then
      VLAN=",tag=$VLAN_INPUT"
      echo -e "  VLAN set to: ${BL}${VLAN_INPUT}${CL}"
    elif [ -z "$VLAN_INPUT" ]; then
      VLAN=""
      echo -e "  VLAN: ${BL}None (default)${CL}"
    else
      VLAN=""
      echo -e "  Invalid VLAN, using default: ${BL}None${CL}"
    fi
  fi
fi

check_root
arch_check
pve_check

post_to_api_vm

msg_info "Validating Storage"
while read -r line; do
  TAG=$(echo $line | awk '{print $1}')
  TYPE=$(echo $line | awk '{printf "%-10s", $2}')
  FREE=$(echo $line | numfmt --field 4-6 --from-unit=K --to=iec --format %.2f | awk '{printf( "%9sB", $6)}')
  ITEM="  Type: $TYPE Free: $FREE "
  OFFSET=2
  if [[ $((${#ITEM} + $OFFSET)) -gt ${MSG_MAX_LENGTH:-} ]]; then
    MSG_MAX_LENGTH=$((${#ITEM} + $OFFSET))
  fi
  STORAGE_MENU+=("$TAG" "$ITEM" "OFF")
done < <(pvesm status -content images | awk 'NR>1')
VALID=$(pvesm status -content images | awk 'NR>1')
if [ -z "$VALID" ]; then
  msg_error "Unable to detect a valid storage location."
  exit
elif [ $((${#STORAGE_MENU[@]} / 3)) -eq 1 ]; then
  STORAGE=${STORAGE_MENU[0]}
else
  while [ -z "${STORAGE:+x}" ]; do
    STORAGE=$(whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --title "Storage Pools" --radiolist \
      "Select storage pool for ${HN}:\n" \
      16 $(($MSG_MAX_LENGTH + 23)) 6 \
      "${STORAGE_MENU[@]}" 3>&1 1>&2 2>&3)
  done
fi
msg_ok "Using ${BL}$STORAGE${CL} for Storage"

# Install libguestfs-tools if not present
if ! command -v virt-customize &>/dev/null; then
  msg_info "Installing libguestfs-tools"
  apt-get -qq update >/dev/null
  apt-get -qq install libguestfs-tools -y >/dev/null
  msg_ok "Installed libguestfs-tools"
fi

msg_info "Downloading Debian 13 Minimal Image"
URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2
echo -e "\n  Source: ${BL}${URL}${CL}"

if ! curl -f#SL -o "$(basename "$URL")" "$URL"; then
  msg_error "Failed to download image"
  exit 1
fi

echo -en "\e[1A\e[0K"
FILE=$(basename $URL)
msg_ok "Downloaded ${BL}${FILE}${CL}"

# Generate random root password
ROOT_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)

msg_info "Installing Docker with userns-remap into image"
# Install Docker and dependencies
virt-customize -q -a "${FILE}" --install qemu-guest-agent,apt-transport-https,ca-certificates,curl,gnupg >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "mkdir -p /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable' > /etc/apt/sources.list.d/docker.list" >/dev/null &&
  virt-customize -q -a "${FILE}" --update >/dev/null &&
  virt-customize -q -a "${FILE}" --install docker-ce,docker-ce-cli,containerd.io,docker-compose-plugin >/dev/null
msg_ok "Installed Docker packages"

msg_info "Configuring Docker userns-remap security"
# Create dockremap user with specific UID/GID ranges
virt-customize -q -a "${FILE}" --run-command "useradd -r -s /usr/sbin/nologin -u 100000 dockremap" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'dockremap:100000:65536' >> /etc/subuid" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'dockremap:100000:65536' >> /etc/subgid" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "mkdir -p /etc/docker" >/dev/null

# Configure Docker daemon with userns-remap
virt-customize -q -a "${FILE}" --run-command "cat > /etc/docker/daemon.json << 'DOCKER_EOF'
{
  \"userns-remap\": \"dockremap\",
  \"log-driver\": \"json-file\",
  \"log-opts\": {
    \"max-size\": \"10m\",
    \"max-file\": \"3\"
  },
  \"storage-driver\": \"overlay2\"
}
DOCKER_EOF
" >/dev/null

# Enable and configure Docker service
virt-customize -q -a "${FILE}" --run-command "systemctl enable docker" >/dev/null &&
  virt-customize -q -a "${FILE}" --hostname "${HN}" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo -n > /etc/machine-id" >/dev/null
msg_ok "Configured Docker with userns-remap"

msg_info "Configuring Elasticsearch kernel parameters"
# Set vm.max_map_count permanently for Elasticsearch
virt-customize -q -a "${FILE}" --run-command "echo 'vm.max_map_count=262144' >> /etc/sysctl.conf" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf" >/dev/null
msg_ok "Configured kernel parameters for Elasticsearch"

msg_info "Creating user account with Docker access"
# Install sudo, openssh-server, set root password, and create debian user with password and docker group access
virt-customize -q -a "${FILE}" --install sudo,openssh-server >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'root:${ROOT_PASSWORD}' | chpasswd" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "useradd -m -s /bin/bash debian" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'debian:debian' | chpasswd" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "usermod -aG sudo,docker debian" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "echo 'debian ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/debian" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "chmod 440 /etc/sudoers.d/debian" >/dev/null
msg_ok "Created user: ${BL}debian${CL} / ${BL}debian${CL}"

msg_info "Deploying Elasticsearch stack configuration"
# Create ELK directory structure
virt-customize -q -a "${FILE}" --run-command "mkdir -p /docker/elk" >/dev/null

# Create docker-compose.yml for Elasticsearch
virt-customize -q -a "${FILE}" --run-command "cat > /docker/elk/docker-compose.yml << 'COMPOSE_EOF'
services:
  setup:
    container_name: setup
    image: docker.elastic.co/elasticsearch/elasticsearch:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
    user: \"0\"
    command: >
      bash -c '
        if [ x\${ELASTIC_PASSWORD} == x ]; then
          echo \"Set the ELASTIC_PASSWORD environment variable in the .env file\";
          exit 1;
        elif [ x\${KIBANA_PASSWORD} == x ]; then
          echo \"Set the KIBANA_PASSWORD environment variable in the .env file\";
          exit 1;
        fi;
        if [ ! -f config/certs/ca.zip ]; then
          echo \"Creating CA\";
          bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip;
          unzip config/certs/ca.zip -d config/certs;
        fi;
        if [ ! -f config/certs/certs.zip ]; then
          echo \"Creating certs\";
          echo -ne \
          \"instances:\n\"\
          \"  - name: es01\n\"\
          \"    dns:\n\"\
          \"      - es01\n\"\
          \"      - localhost\n\"\
          \"    ip:\n\"\
          \"      - 127.0.0.1\n\"\
          \"  - name: es02\n\"\
          \"    dns:\n\"\
          \"      - es02\n\"\
          \"      - localhost\n\"\
          \"    ip:\n\"\
          \"      - 127.0.0.1\n\"\
          \"  - name: es03\n\"\
          \"    dns:\n\"\
          \"      - es03\n\"\
          \"      - localhost\n\"\
          \"    ip:\n\"\
          \"      - 127.0.0.1\n\"\
          > config/certs/instances.yml;
          bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in config/certs/instances.yml --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key;
          unzip config/certs/certs.zip -d config/certs;
        fi;
        echo \"Setting file permissions\"
        chown -R root:root config/certs;
        find . -type d -exec chmod 750 \{\} \;;
        find . -type f -exec chmod 640 \{\} \;;
        echo \"Waiting for Elasticsearch availability\";
        until curl -s --cacert config/certs/ca/ca.crt https://es01:9200 | grep -q \"missing authentication credentials\"; do sleep 30; done;
        echo \"Setting kibana_system password\";
        until curl -s -X POST --cacert config/certs/ca/ca.crt -u \"elastic:\${ELASTIC_PASSWORD}\" -H \"Content-Type: application/json\" https://es01:9200/_security/user/kibana_system/_password -d \"{\\\"password\\\":\\\"\${KIBANA_PASSWORD}\\\"}\" | grep -q \"^{}\"; do sleep 10; done;
        echo \"All done!\";
      '
    healthcheck:
      test: [\"CMD-SHELL\", \"[ -f config/certs/es01/es01.crt ]\"]
      interval: 1s
      timeout: 5s
      retries: 120

  es01:
    container_name: es01
    depends_on:
      setup:
        condition: service_healthy
    image: docker.elastic.co/elasticsearch/elasticsearch:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata01:/usr/share/elasticsearch/data
    ports:
      - \${ES_PORT}:9200
    environment:
      - node.name=es01
      - cluster.name=\${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es02,es03
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/es01/es01.key
      - xpack.security.http.ssl.certificate=certs/es01/es01.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/es01/es01.key
      - xpack.security.transport.ssl.certificate=certs/es01/es01.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=\${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: \${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          \"CMD-SHELL\",
          \"curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'\",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  es02:
    container_name: es02
    depends_on:
      - es01
    image: docker.elastic.co/elasticsearch/elasticsearch:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata02:/usr/share/elasticsearch/data
    environment:
      - node.name=es02
      - cluster.name=\${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es01,es03
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/es02/es02.key
      - xpack.security.http.ssl.certificate=certs/es02/es02.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/es02/es02.key
      - xpack.security.transport.ssl.certificate=certs/es02/es02.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=\${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: \${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          \"CMD-SHELL\",
          \"curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'\",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  es03:
    container_name: es03
    depends_on:
      - es02
    image: docker.elastic.co/elasticsearch/elasticsearch:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata03:/usr/share/elasticsearch/data
    environment:
      - node.name=es03
      - cluster.name=\${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es01,es02
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/es03/es03.key
      - xpack.security.http.ssl.certificate=certs/es03/es03.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/es03/es03.key
      - xpack.security.transport.ssl.certificate=certs/es03/es03.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=\${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: \${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          \"CMD-SHELL\",
          \"curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'\",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  kibana:
    container_name: kibana
    depends_on:
      es01:
        condition: service_healthy
      es02:
        condition: service_healthy
      es03:
        condition: service_healthy
    image: docker.elastic.co/kibana/kibana:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/kibana/config/certs
      - kibanadata:/usr/share/kibana/data
    ports:
      - \${KIBANA_PORT}:5601
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://es01:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=\${KIBANA_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=\${XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY}
    mem_limit: \${MEM_LIMIT}
    healthcheck:
      test:
        [
          \"CMD-SHELL\",
          \"curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'\",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

volumes:
  certs:
    driver: local
  esdata01:
    driver: local
  esdata02:
    driver: local
  esdata03:
    driver: local
  kibanadata:
    driver: local
COMPOSE_EOF
" >/dev/null

# Create .env file with randomized passwords
virt-customize -q -a "${FILE}" --run-command "cat > /docker/elk/.env << 'ENV_EOF'
# Password for the 'elastic' user (at least 6 characters)
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

# Password for the 'kibana_system' user (at least 6 characters)
KIBANA_PASSWORD=${KIBANA_PASSWORD}

# Version of Elastic products
STACK_VERSION=9.2.0

# Set the cluster name
CLUSTER_NAME=docker-cluster

# Set to 'basic' or 'trial' to automatically start the 30-day trial
LICENSE=basic

# Port to expose Elasticsearch HTTP API to the host
ES_PORT=9200

# Port to expose Kibana to the host
KIBANA_PORT=5601

# Increase or decrease based on the available host memory (in bytes)
# 2GB = 2147483648 bytes (minimum recommended for Elasticsearch)
MEM_LIMIT=2147483648

# Kibana encryption key for saved objects (32 hex characters)
XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${KIBANA_ENCRYPTION_KEY}
ENV_EOF
" >/dev/null

# Create Fleet Server setup script
virt-customize -q -a "${FILE}" --run-command "cat > /docker/elk/setup-fleet.sh << 'FLEET_EOF'
#!/usr/bin/env bash
set -euo pipefail

# ======================================================
# Fully Automatic Fleet Server Bootstrap for Docker ELK
# Handles self-signed certs, dynamic STACK_VERSION, mounts existing Docker volume for SSL
# ======================================================

ES_CONTAINER=\"es01\"
KIBANA_CONTAINER=\"kibana\"
ES_URL=\"https://es01:9200\"
KIBANA_URL=\"http://kibana:5601\"
CA_PATH=\"/usr/share/elasticsearch/config/certs/ca/ca.crt\"
ENV_FILE=\".env\"

# --- Load STACK_VERSION from .env if exists ---
STACK_VERSION=\"8.15.0\" # default
if [ -f \"\$ENV_FILE\" ]; then
    export \$(grep -v '^#' \"\$ENV_FILE\" | xargs)
    STACK_VERSION=\"\${STACK_VERSION:-\$STACK_VERSION}\"
fi

echo \"🚀 Starting Fleet Server setup (ELK \$STACK_VERSION)...\"

# --- Wait until Elasticsearch is ready ---
echo \"⏳ Waiting for Elasticsearch to be ready...\"
until docker exec \"\$ES_CONTAINER\" bash -c \"curl -s -u elastic:\\\$ELASTIC_PASSWORD --cacert \$CA_PATH \$ES_URL >/dev/null 2>&1\"; do
  sleep 5
done
echo \"✅ Elasticsearch is ready.\"

# --- Wait until Kibana is ready ---
echo \"⏳ Waiting for Kibana to be ready...\"
until docker exec \"\$ES_CONTAINER\" bash -c \"curl -s \$KIBANA_URL/api/status | grep -q '\\\"overall\\\":{\\\"level\\\":\\\"available\\\"'\"; do
  sleep 5
done
echo \"✅ Kibana is ready.\"

# --- Create Fleet Server service token ---
echo \"🔐 Creating Fleet Server service token...\"
SERVICE_TOKEN_JSON=\$(docker exec \"\$ES_CONTAINER\" bash -c \\
  \"curl -s -u elastic:\\\$ELASTIC_PASSWORD --cacert \$CA_PATH -X POST '\$ES_URL/_security/service/elastic/fleet-server/credential/token'\")
SERVICE_TOKEN=\$(echo \"\$SERVICE_TOKEN_JSON\" | grep -oP '\"value\"\\s*:\\s*\"\\K[^\"]+')
echo \"✅ Service token created.\"

# --- Check if Fleet Server policy exists ---
echo \"🔍 Checking for existing Fleet Server policy...\"
POLICY_JSON=\$(docker exec \"\$ES_CONTAINER\" bash -c \\
  \"curl -s -u elastic:\\\$ELASTIC_PASSWORD -X GET '\$KIBANA_URL/api/fleet/agent_policies' -H 'kbn-xsrf: true'\")
POLICY_EXISTS=\$(echo \"\$POLICY_JSON\" | grep -o '\"id\":\"fleet-server-policy\"' || true)

if [ -z \"\$POLICY_EXISTS\" ]; then
  echo \"⚙️  Creating Fleet Server agent policy...\"
  docker exec \"\$ES_CONTAINER\" bash -c \\
    \"curl -s -u elastic:\\\$ELASTIC_PASSWORD -X POST '\$KIBANA_URL/api/fleet/agent_policies' \\
     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \\
     -d '{\\\"id\\\":\\\"fleet-server-policy\\\",\\\"name\\\":\\\"Fleet Server policy\\\",\\\"namespace\\\":\\\"default\\\",\\\"has_fleet_server\\\":true}'\" >/dev/null
  echo \"✅ Fleet Server policy created.\"
else
  echo \"✅ Fleet Server policy already exists.\"
fi

# --- Create Fleet enrollment token ---
echo \"🎟️ Creating Fleet enrollment token...\"
ENROLLMENT_JSON=\$(docker exec \"\$ES_CONTAINER\" bash -c \\
  \"curl -s -u elastic:\\\$ELASTIC_PASSWORD -X POST '\$KIBANA_URL/api/fleet/enrollment_api_keys' \\
   -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \\
   -d '{\\\"policy_id\\\":\\\"fleet-server-policy\\\"}'\")
ENROLLMENT_TOKEN=\$(echo \"\$ENROLLMENT_JSON\" | grep -oP '\\\"api_key\\\"\\s*:\\s*\\\"\\K[^\\\"]+')
echo \"✅ Enrollment token created.\"

# --- Start Fleet Server container ---
echo \"📥 Pulling Fleet Server image...\"
docker pull docker.elastic.co/elastic-agent/elastic-agent:\"\$STACK_VERSION\"

echo \"🚀 Starting Fleet Server container...\"
docker run -d --name fleet-server \\
  --net \$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' \"\$ES_CONTAINER\") \\
  -v elk_certs:/usr/share/elasticsearch/config/certs:ro \\
  -e FLEET_SERVER_ENABLE=1 \\
  -e FLEET_SERVER_ELASTICSEARCH_HOST=\"\$ES_URL\" \\
  -e FLEET_SERVER_SERVICE_TOKEN=\"\$SERVICE_TOKEN\" \\
  -e FLEET_SERVER_ELASTICSEARCH_CA=\"\$CA_PATH\" \\
  -e FLEET_ENROLL=1 \\
  -e FLEET_ENROLLMENT_TOKEN=\"\$ENROLLMENT_TOKEN\" \\
  -e FLEET_URL=https://fleet-server:8220 \\
  -p 8220:8220 \\
  docker.elastic.co/elastic-agent/elastic-agent:\"\$STACK_VERSION\"

echo \"✅ Fleet Server container started.\"
echo \"⏳ Waiting for Fleet Server to be healthy...\"
while ! curl -s -k https://localhost:8220/api/status 2>/dev/null | grep -q '\"status\":\"HEALTHY\"'; do
  echo \"   Fleet Server not ready yet, waiting...\"
  sleep 5
done
echo \"✅ Fleet Server is healthy!\"

# --- Add Fleet Server to docker-compose.yml ---
echo \"📝 Adding Fleet Server to docker-compose.yml...\"

# Create fleet-server service definition in a temp file
cat > /tmp/fleet-service.yml << 'FLEET_SERVICE_EOF'

  fleet-server:
    container_name: fleet-server
    depends_on:
      es01:
        condition: service_healthy
      kibana:
        condition: service_healthy
    image: docker.elastic.co/elastic-agent/elastic-agent:\${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs:ro
    ports:
      - 8220:8220
    environment:
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://es01:9200
      - FLEET_SERVER_SERVICE_TOKEN=\${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_ELASTICSEARCH_CA=/usr/share/elasticsearch/config/certs/ca/ca.crt
      - FLEET_ENROLL=1
      - FLEET_ENROLLMENT_TOKEN=\${FLEET_ENROLLMENT_TOKEN}
      - FLEET_URL=https://fleet-server:8220
    mem_limit: \${MEM_LIMIT}
    restart: unless-stopped
    healthcheck:
      test:
        [
          \"CMD-SHELL\",
          \"curl -s -k https://localhost:8220/api/status | grep -q '\\\"status\\\":\\\"HEALTHY\\\"'\",
        ]
      interval: 10s
      timeout: 10s
      retries: 120
FLEET_SERVICE_EOF

# Insert the fleet-server service before the volumes section
awk '/^volumes:/ {system(\"cat /tmp/fleet-service.yml\")} {print}' docker-compose.yml > /tmp/docker-compose-new.yml
mv /tmp/docker-compose-new.yml docker-compose.yml
rm /tmp/fleet-service.yml


# --- Save tokens to .env file ---
echo \"💾 Saving Fleet tokens to .env file...\"
cat >> .env << ENV_FLEET_EOF

# Fleet Server tokens (auto-generated during setup)
FLEET_SERVICE_TOKEN=\${SERVICE_TOKEN}
FLEET_ENROLLMENT_TOKEN=\${ENROLLMENT_TOKEN}
ENV_FLEET_EOF

# --- Stop manual container and start via docker compose ---
echo \"🔄 Transitioning Fleet Server to docker compose management...\"
docker stop fleet-server >/dev/null 2>&1 || true
docker rm fleet-server >/dev/null 2>&1 || true
docker compose up -d fleet-server

echo \"\"
echo \"✅ Fleet Server successfully added to ELK stack!\"
echo \"   - Fleet Server is now managed by docker compose\"
echo \"   - Service will persist across docker compose restarts\"
echo \"   - Access Fleet at: http://localhost:5601/app/fleet\"
FLEET_EOF
" >/dev/null

# Set proper ownership and permissions
virt-customize -q -a "${FILE}" --run-command "chmod 600 /docker/elk/.env" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "chmod +x /docker/elk/setup-fleet.sh" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "chown -R debian:debian /docker" >/dev/null

# Create state directory for ELK service markers
virt-customize -q -a "${FILE}" --run-command "mkdir -p /var/lib/elk" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "chown debian:debian /var/lib/elk" >/dev/null

# Create elk-stack.service for first-boot ELK stack setup
virt-customize -q -a "${FILE}" --run-command "cat > /etc/systemd/system/elk-stack.service << 'SYSTEMD_ELK_EOF'
[Unit]
Description=Elasticsearch Stack - First Boot Setup
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
ConditionPathExists=!/var/lib/elk/.elk-initialized

[Service]
Type=oneshot
User=debian
Group=debian
WorkingDirectory=/docker/elk
ExecStart=/usr/bin/docker compose up -d
ExecStartPost=/usr/bin/touch /var/lib/elk/.elk-initialized

[Install]
WantedBy=multi-user.target
SYSTEMD_ELK_EOF
" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "systemctl daemon-reload && systemctl enable elk-stack.service" >/dev/null

# Create fleet-setup.service for first-boot Fleet enrollment
virt-customize -q -a "${FILE}" --run-command "cat > /etc/systemd/system/fleet-setup.service << 'SYSTEMD_FLEET_EOF'
[Unit]
Description=Elasticsearch Fleet Server - First Boot Enrollment
After=elk-stack.service
ConditionPathExists=/var/lib/elk/.elk-initialized
ConditionPathExists=!/var/lib/elk/.fleet-initialized

[Service]
Type=oneshot
User=debian
Group=debian
WorkingDirectory=/docker/elk
ExecStartPre=/bin/bash -c 'while ! curl -sf http://localhost:5601/api/status >/dev/null 2>&1; do echo \"Waiting for Kibana...\"; sleep 5; done; sleep 10'
ExecStart=/docker/elk/setup-fleet.sh
ExecStartPost=/usr/bin/touch /var/lib/elk/.fleet-initialized

[Install]
WantedBy=multi-user.target
SYSTEMD_FLEET_EOF
" >/dev/null &&
  virt-customize -q -a "${FILE}" --run-command "systemctl daemon-reload && systemctl enable fleet-setup.service" >/dev/null

msg_ok "Deployed Elasticsearch stack configuration"

msg_info "Expanding root partition to ${DISK_SIZE}"
qemu-img create -f qcow2 expanded.qcow2 ${DISK_SIZE} >/dev/null 2>&1
virt-resize --expand /dev/sda1 ${FILE} expanded.qcow2 >/dev/null 2>&1
mv expanded.qcow2 ${FILE} >/dev/null 2>&1
msg_ok "Expanded image to ${DISK_SIZE}"

# Determine storage type and set appropriate disk parameters
STORAGE_TYPE=$(pvesm status -storage $STORAGE | awk 'NR>1 {print $2}')
case $STORAGE_TYPE in
nfs | dir)
  DISK_EXT=".qcow2"
  DISK_REF="$VMID/"
  DISK_IMPORT="-format qcow2"
  THIN=""
  ;;
btrfs)
  DISK_EXT=".raw"
  DISK_REF="$VMID/"
  DISK_IMPORT="-format raw"
  FORMAT=",efitype=4m"
  THIN=""
  ;;
*)
  DISK_EXT=""
  DISK_REF=""
  DISK_IMPORT=""
  THIN="discard=on,ssd=1,"
  ;;
esac

for i in {0,1}; do
  disk="DISK$i"
  eval DISK${i}=vm-${VMID}-disk-${i}${DISK_EXT:-}
  eval DISK${i}_REF=${STORAGE}:${DISK_REF:-}${!disk}
done

msg_info "Creating ELK Docker VM"
qm create $VMID -agent 1${MACHINE} -tablet 0 -localtime 1 -bios ovmf${CPU_TYPE} -cores $CORE_COUNT -memory $RAM_SIZE \
  -name $HN -tags elk,docker,elasticsearch -net0 virtio,bridge=$BRG,macaddr=$MAC$VLAN$MTU -onboot 0 -ostype l26 -scsihw virtio-scsi-pci

pvesm alloc $STORAGE $VMID $DISK0 4M 1>&/dev/null
qm importdisk $VMID ${FILE} $STORAGE ${DISK_IMPORT:-} 1>&/dev/null

qm set $VMID \
  -efidisk0 ${DISK0_REF}${FORMAT} \
  -scsi0 ${DISK1_REF},${DISK_CACHE}${THIN}size=${DISK_SIZE} \
  -boot order=scsi0 \
  -serial0 socket >/dev/null

qm set $VMID --agent enabled=1 >/dev/null

msg_ok "VM Created (ID: ${BL}${VMID}${CL})"

DESCRIPTION="<div align='center'><h2>Debian 13 + Docker + Elasticsearch</h2><p>3-node Elasticsearch cluster with Kibana</p><p>RAM: ${RAM_SIZE}MB | CPU: ${CORE_COUNT} cores | Disk: ${DISK_SIZE}</p><p style='font-size:12px; color:#666;'>Docker userns-remap enabled | vm.max_map_count configured</p></div>"
qm set "$VMID" -description "$DESCRIPTION" >/dev/null

if (whiptail --backtitle "Proxmox VE - Debian 13 + ELK" --title "START VM" --yesno "Start the VM now?" --defaultno 10 60); then
  msg_info "Starting VM"
  qm start $VMID
  msg_ok "VM Started"
  START_VM="yes"
fi

echo -e "\n${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "${GN}  ✅ Debian 13 + Docker + Elasticsearch Stack Created!${CL}"
echo -e "${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "  🆔 VM ID:       ${BL}${VMID}${CL}"
echo -e "  🏠 Name:        ${BL}${HN}${CL}"
echo -e "  💾 Disk:        ${BL}${DISK_SIZE}${CL}"
echo -e "  🧠 CPU:         ${BL}${CORE_COUNT} cores${CL}"
echo -e "  🛠️  RAM:         ${BL}${RAM_SIZE}MB${CL}"
echo -e "  📦 Storage:     ${BL}${STORAGE}${CL}"
echo -e "  🐋 Docker:      ${GN}Installed with userns-remap${CL}"
echo -e "  🔍 ELK Stack:   ${GN}3-node Elasticsearch + Kibana${CL}"
if [ "$START_VM" == "yes" ]; then
  echo -e "  ▶️  Status:      ${GN}Running${CL}"
else
  echo -e "  ⏸️  Status:      ${YW}Stopped${CL}"
fi
echo -e "${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "\n  ${BL}Login Credentials:${CL}"
echo -e "    • Root password: ${GN}${ROOT_PASSWORD}${CL}"
echo -e "    • Username: ${GN}debian${CL}"
echo -e "    • Password: ${GN}debian${CL}"
echo -e "    • Sudo access: ${GN}Yes (passwordless)${CL}"
echo -e "    • Docker access: ${GN}Yes (docker group member)${CL}"
echo -e "\n  ${BL}Elasticsearch Credentials:${CL}"
echo -e "    • Elastic user: ${GN}elastic${CL}"
echo -e "    • Elastic pass: ${GN}${ELASTIC_PASSWORD}${CL}"
echo -e "    • Kibana user:  ${GN}kibana_system${CL}"
echo -e "    • Kibana pass:  ${GN}${KIBANA_PASSWORD}${CL}"
echo -e "\n  ${BL}ELK Stack Configuration:${CL}"
echo -e "    • Location: ${YW}/docker/elk/${CL}"
echo -e "    • Elasticsearch: ${YW}https://<vm-ip>:9200${CL}"
echo -e "    • Kibana: ${YW}http://<vm-ip>:5601${CL}"
echo -e "    • Fleet Server: ${YW}https://<vm-ip>:8220${CL}"
echo -e "    • Kernel: ${GN}vm.max_map_count=262144 (configured)${CL}"
echo -e "    • Credentials: ${YW}/docker/elk/.env${CL}"
echo -e "\n  ${BL}Automated Setup:${CL}"
echo -e "    • ${GN}First boot:${CL} ELK stack and Fleet server start automatically"
echo -e "    • ${GN}Subsequent boots:${CL} Services remain enabled but skip re-initialization"
echo -e "    • ${GN}State files:${CL} /var/lib/elk/.elk-initialized, .fleet-initialized"
echo -e "\n  ${BL}Useful Commands:${CL}"
echo -e "    • Monitor stack: ${YW}cd /docker/elk && docker compose ps${CL}"
echo -e "    • View logs: ${YW}docker compose logs -f${CL}"
echo -e "    • Restart stack: ${YW}docker compose restart${CL}"
echo -e "    • Stop stack: ${YW}docker compose down${CL}"
echo -e "    • Re-run setup: ${YW}rm /var/lib/elk/.* && reboot${CL}\n"
