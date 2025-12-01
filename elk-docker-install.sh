#!/usr/bin/env bash

# Docker + Elasticsearch Stack Installer
# Works on: Debian, Ubuntu, Linux Mint, Pop!_OS, and other Debian-based distros
# License: MIT

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

function error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  local error_message="${RD}[ERROR]${CL} in line ${RD}$line_number${CL}: exit code ${RD}$exit_code${CL}: while executing command ${YW}$command${CL}"
  echo -e "\n$error_message\n"
  exit 1
}

function header_info {
  clear
  cat <<"EOF"
    ____       __    _                   ________    __ __
   / __ \___  / /_  (_)___ _____        / ____/ /   / //_/
  / / / / _ \/ __ \/ / __ `/ __ \______/ __/ / /   / ,<
 / /_/ /  __/ /_/ / / /_/ / / / /_____/ /___/ /___/ /| |
/_____/\___/_.___/_/\__,_/_/ /_/     /_____/_____/_/ |_|

      DEBIAN-based + DOCKER + ELASTICSEARCH STACK
EOF
}

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
  if [[ "$(id -u)" -ne 0 ]]; then
    clear
    msg_error "Please run this script as root or with sudo."
    echo -e "\nUsage: sudo $0\n"
    exit 1
  fi
}

function check_debian_based() {
  if [ ! -f /etc/os-release ]; then
    msg_error "Cannot detect OS. /etc/os-release not found."
    exit 1
  fi

  source /etc/os-release

  # Check if it's Debian-based (Debian, Ubuntu, Mint, Pop!_OS, etc.)
  if [[ ! "$ID" =~ ^(debian|ubuntu|linuxmint|pop|elementary|zorin)$ ]] && \
     [[ ! "$ID_LIKE" =~ (debian|ubuntu) ]]; then
    msg_error "This script only works on Debian-based distributions."
    msg_error "Detected OS: $PRETTY_NAME"
    exit 1
  fi

  msg_ok "Detected: ${BL}${PRETTY_NAME}${CL}"
}

function arch_check() {
  if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    msg_error "This script only supports amd64/x86_64 architecture."
    echo -e "Detected architecture: $(dpkg --print-architecture)"
    exit 1
  fi
}

function check_memory() {
  local total_mem_mb=$(free -m | awk '/^Mem:/{print $2}')

  if [ "$total_mem_mb" -lt 4096 ]; then
    msg_error "Insufficient RAM: ${total_mem_mb}MB detected"
    msg_error "Minimum required: 4096MB (4GB)"
    msg_error "Recommended: 8192MB (8GB) or more for ELK stack"
    exit 1
  fi

  msg_ok "RAM: ${BL}${total_mem_mb}MB${CL} (sufficient)"
}

function check_disk_space() {
  local available_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')

  if [ "$available_gb" -lt 10 ]; then
    msg_error "Insufficient disk space: ${available_gb}GB available"
    msg_error "Minimum required: 10GB free"
    msg_error "Recommended: 50GB or more"
    exit 1
  fi

  msg_ok "Disk space: ${BL}${available_gb}GB${CL} available"
}

header_info
echo -e "\n"

msg_info "Performing system checks"
check_root
arch_check
check_debian_based
check_memory
check_disk_space
msg_ok "System checks passed"

# Generate random passwords (16 characters for security)
ELASTIC_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
KIBANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
# Generate random 32 hex character encryption key for Kibana
KIBANA_ENCRYPTION_KEY=$(openssl rand -hex 16)

echo -e "\n${BGN}═══════════════════════════════════════════════════════════${CL}"
echo -e "${BGN}  Debian-based + Docker + Elasticsearch Stack${CL}"
echo -e "${BGN}═══════════════════════════════════════════════════════════${CL}"
echo -e "  🐋 Docker:       ${BL}Latest with userns-remap${CL}"
echo -e "  🔍 Elasticsearch:${GN}3-node cluster + Kibana${CL}"
echo -e "  🔧 Fleet Server: ${GN}Automated setup included${CL}"
echo -e "  ⚙️  Kernel:       ${BL}vm.max_map_count will be configured${CL}"
echo -e "${BGN}═══════════════════════════════════════════════════════════${CL}\n"

read -p "Do you want to proceed with installation? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "  ${RD}Installation cancelled${CL}\n"
  exit 0
fi

msg_info "Updating system packages"
if ! apt-get update -qq 2>&1 | grep -v "^Get:" | grep -v "^Hit:" | grep -v "^Ign:" >/dev/null; then
  msg_ok "System packages updated"
else
  msg_error "Failed to update package lists"
  exit 1
fi

msg_info "Installing prerequisites"
# Note: apt-transport-https is deprecated and not needed on modern Debian/Ubuntu
# It's been built into apt since version 1.5
# software-properties-common is not needed since we add repos manually
PREREQ_PACKAGES="ca-certificates curl gnupg"

# Install packages one by one to identify any issues
for pkg in $PREREQ_PACKAGES; do
  if ! dpkg -l | grep -q "^ii  $pkg "; then
    if ! apt-get install -qq -y "$pkg" 2>&1 | grep -v "^Selecting" | grep -v "^Preparing" | grep -v "^Unpacking" | grep -v "^Setting up" | grep -v "^Processing" >/dev/null; then
      : # Package installed successfully
    else
      msg_error "Failed to install $pkg"
      exit 1
    fi
  fi
done

msg_ok "Prerequisites installed"

# Check if Docker is already installed
if command -v docker &>/dev/null; then
  DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
  msg_ok "Docker already installed: ${BL}${DOCKER_VERSION}${CL}"
else
  msg_info "Installing Docker"

  # Detect OS from /etc/os-release
  source /etc/os-release

  # Determine the base distribution for Docker repo
  if [[ "$ID" == "ubuntu" ]] || [[ "$ID_LIKE" =~ ubuntu ]]; then
    DOCKER_DISTRO="ubuntu"
    DOCKER_CODENAME="${VERSION_CODENAME:-$(cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2)}"
  elif [[ "$ID" == "debian" ]] || [[ "$ID_LIKE" =~ debian ]]; then
    DOCKER_DISTRO="debian"
    DOCKER_CODENAME="${VERSION_CODENAME:-$(cat /etc/os-release | grep VERSION_CODENAME | cut -d= -f2)}"
  else
    # Fallback to debian for other Debian-based distros
    DOCKER_DISTRO="debian"
    DOCKER_CODENAME="${VERSION_CODENAME:-bookworm}"
  fi

  # Add Docker's official GPG key
  install -m 0755 -d /etc/apt/keyrings
  if ! curl -fsSL https://download.docker.com/linux/${DOCKER_DISTRO}/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null; then
    msg_error "Failed to add Docker GPG key"
    exit 1
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg

  # Add Docker repository
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DOCKER_DISTRO} \
    ${DOCKER_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list >/dev/null

  # Install Docker
  msg_info "Updating package lists for Docker"
  if ! apt-get update -qq 2>&1 | grep -v "^Get:" | grep -v "^Hit:" | grep -v "^Ign:" >/dev/null; then
    msg_ok "Package lists updated"
  fi

  msg_info "Installing Docker packages (this may take a few minutes)"
  if apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>&1 | tee /tmp/docker-install.log | grep -q "^Setting up docker-ce"; then
    msg_ok "Docker installed"
    rm -f /tmp/docker-install.log
  else
    msg_error "Docker installation failed. Check /tmp/docker-install.log for details"
    exit 1
  fi
fi

msg_info "Configuring Docker with userns-remap security"
# Create dockremap user with specific UID/GID ranges
if ! id dockremap &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -u 100000 dockremap
fi

# Configure subuid and subgid
if ! grep -q "dockremap:100000:65536" /etc/subuid; then
  echo "dockremap:100000:65536" >> /etc/subuid
fi
if ! grep -q "dockremap:100000:65536" /etc/subgid; then
  echo "dockremap:100000:65536" >> /etc/subgid
fi

# Configure Docker daemon with userns-remap
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'DOCKER_EOF'
{
  "userns-remap": "dockremap",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
DOCKER_EOF

# Restart Docker to apply changes
systemctl restart docker
systemctl enable docker >/dev/null 2>&1

msg_ok "Docker configured with userns-remap"

msg_info "Configuring Elasticsearch kernel parameters"
# Set vm.max_map_count permanently for Elasticsearch
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf
sysctl -w vm.max_map_count=262144 >/dev/null 2>&1
msg_ok "Kernel parameters configured (vm.max_map_count=262144)"

msg_info "Creating ELK directory structure"
mkdir -p /opt/elk
chown root:root /opt/elk
chmod 755 /opt/elk
msg_ok "Created /opt/elk directory"

msg_info "Verifying system time synchronization"
# Install and configure NTP/timesyncd
if ! systemctl is-active --quiet systemd-timesyncd; then
  systemctl enable systemd-timesyncd >/dev/null 2>&1
  systemctl start systemd-timesyncd >/dev/null 2>&1
fi

# Wait for time sync
timeout=30
while [ $timeout -gt 0 ]; do
  if timedatectl status | grep -q "System clock synchronized: yes"; then
    break
  fi
  sleep 1
  timeout=$((timeout - 1))
done

CURRENT_TIME=$(date +%s)
EXPECTED_MIN=$(date -d "2024-01-01" +%s)
if [ $CURRENT_TIME -lt $EXPECTED_MIN ]; then
  msg_error "System time appears incorrect: $(date)"
  echo -e "  Please verify system time before continuing."
  echo -e "  Current time: $(date)"
  echo -e "  Run: timedatectl set-ntp true"
  exit 1
fi

msg_ok "System time synchronized: $(date)"

msg_info "Deploying Elasticsearch stack configuration"
# Create docker-compose.yml for Elasticsearch
cat > /opt/elk/docker-compose.yml << 'COMPOSE_EOF'
services:
  setup:
    container_name: setup
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
    user: "0"
    command: >
      bash -c '
        if [ x${ELASTIC_PASSWORD} == x ]; then
          echo "Set the ELASTIC_PASSWORD environment variable in the .env file";
          exit 1;
        elif [ x${KIBANA_PASSWORD} == x ]; then
          echo "Set the KIBANA_PASSWORD environment variable in the .env file";
          exit 1;
        fi;
        if [ ! -f config/certs/ca.zip ]; then
          echo "Creating CA";
          bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip;
          unzip config/certs/ca.zip -d config/certs;
        fi;
        if [ ! -f config/certs/certs.zip ]; then
          echo "Creating certs";
          echo -ne \
          "instances:\n"\
          "  - name: es01\n"\
          "    dns:\n"\
          "      - es01\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          "  - name: es02\n"\
          "    dns:\n"\
          "      - es02\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          "  - name: es03\n"\
          "    dns:\n"\
          "      - es03\n"\
          "      - localhost\n"\
          "    ip:\n"\
          "      - 127.0.0.1\n"\
          > config/certs/instances.yml;
          bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in config/certs/instances.yml --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key;
          unzip config/certs/certs.zip -d config/certs;
        fi;
        echo "Setting file permissions"
        chown -R root:root config/certs;
        find . -type d -exec chmod 750 \{\} \;;
        find . -type f -exec chmod 640 \{\} \;;
        echo "Waiting for Elasticsearch availability";
        until curl -s --cacert config/certs/ca/ca.crt https://es01:9200 | grep -q "missing authentication credentials"; do sleep 30; done;
        echo "Setting kibana_system password";
        until curl -s -X POST --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" https://es01:9200/_security/user/kibana_system/_password -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do sleep 10; done;
        echo "All done!";
      '
    healthcheck:
      test: ["CMD-SHELL", "[ -f config/certs/es01/es01.crt ]"]
      interval: 1s
      timeout: 5s
      retries: 120

  es01:
    container_name: es01
    depends_on:
      setup:
        condition: service_healthy
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata01:/usr/share/elasticsearch/data
    ports:
      - ${ES_PORT}:9200
    environment:
      - node.name=es01
      - cluster.name=${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es02,es03
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
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
      - xpack.license.self_generated.type=${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: ${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  es02:
    container_name: es02
    depends_on:
      - es01
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata02:/usr/share/elasticsearch/data
    environment:
      - node.name=es02
      - cluster.name=${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es01,es03
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
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
      - xpack.license.self_generated.type=${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: ${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

  es03:
    container_name: es03
    depends_on:
      - es02
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata03:/usr/share/elasticsearch/data
    environment:
      - node.name=es03
      - cluster.name=${CLUSTER_NAME}
      - cluster.initial_master_nodes=es01,es02,es03
      - discovery.seed_hosts=es01,es02
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
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
      - xpack.license.self_generated.type=${LICENSE}
      - xpack.ml.use_auto_machine_memory_percent=true
    mem_limit: ${MEM_LIMIT}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'",
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
    image: docker.elastic.co/kibana/kibana:${STACK_VERSION}
    volumes:
      - certs:/usr/share/kibana/config/certs
      - kibanadata:/usr/share/kibana/data
    ports:
      - ${KIBANA_PORT}:5601
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://es01:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY}
    mem_limit: ${MEM_LIMIT}
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'",
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

# Create .env file with randomized passwords
cat > /opt/elk/.env << ENV_EOF
# Password for the 'elastic' user (at least 6 characters)
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

# Password for the 'kibana_system' user (at least 6 characters)
KIBANA_PASSWORD=${KIBANA_PASSWORD}

# Version of Elastic products
STACK_VERSION=9.2.1

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

# Set proper permissions
chmod 600 /opt/elk/.env
chmod 644 /opt/elk/docker-compose.yml

msg_ok "Elasticsearch stack configuration deployed"

msg_info "Creating Fleet Server setup script"
cat > /opt/elk/setup-fleet.sh << 'FLEET_EOF'
#!/usr/bin/env bash
set -euo pipefail

# ======================================================
# Fully Automatic Fleet Server Bootstrap for Docker ELK
# Handles self-signed certs, dynamic STACK_VERSION, mounts existing Docker volume for SSL
# ======================================================

ES_CONTAINER="es01"
KIBANA_CONTAINER="kibana"
ES_URL="https://es01:9200"
KIBANA_URL="http://kibana:5601"
CA_PATH="/usr/share/elasticsearch/config/certs/ca/ca.crt"
ENV_FILE=".env"

# --- Load STACK_VERSION from .env if exists ---
STACK_VERSION="9.2.0" # default
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
    STACK_VERSION="${STACK_VERSION:-$STACK_VERSION}"
fi

echo "🚀 Starting Fleet Server setup (ELK $STACK_VERSION)..."

# --- Wait until Elasticsearch is ready ---
echo "⏳ Waiting for Elasticsearch to be ready..."
until docker exec "$ES_CONTAINER" bash -c "curl -s -u elastic:\$ELASTIC_PASSWORD --cacert $CA_PATH $ES_URL >/dev/null 2>&1"; do
  sleep 5
done
echo "✅ Elasticsearch is ready."

# --- Wait until Kibana is ready ---
echo "⏳ Waiting for Kibana to be ready..."
until docker exec "$ES_CONTAINER" bash -c "curl -s $KIBANA_URL/api/status | grep -q '\"overall\":{\"level\":\"available\"'"; do
  sleep 5
done
echo "✅ Kibana is ready."

# --- Create Fleet Server service token ---
echo "🔐 Creating Fleet Server service token..."
SERVICE_TOKEN_JSON=$(docker exec "$ES_CONTAINER" bash -c \
  "curl -s -u elastic:\$ELASTIC_PASSWORD --cacert $CA_PATH -X POST '$ES_URL/_security/service/elastic/fleet-server/credential/token'")
SERVICE_TOKEN=$(echo "$SERVICE_TOKEN_JSON" | grep -oP '"value"\s*:\s*"\K[^"]+')
echo "✅ Service token created."

# --- Check if Fleet Server policy exists ---
echo "🔍 Checking for existing Fleet Server policy..."
POLICY_JSON=$(docker exec "$ES_CONTAINER" bash -c \
  "curl -s -u elastic:\$ELASTIC_PASSWORD -X GET '$KIBANA_URL/api/fleet/agent_policies' -H 'kbn-xsrf: true'")
POLICY_EXISTS=$(echo "$POLICY_JSON" | grep -o '"id":"fleet-server-policy"' || true)

if [ -z "$POLICY_EXISTS" ]; then
  echo "⚙️  Creating Fleet Server agent policy..."
  docker exec "$ES_CONTAINER" bash -c \
    "curl -s -u elastic:\$ELASTIC_PASSWORD -X POST '$KIBANA_URL/api/fleet/agent_policies' \
     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
     -d '{\"id\":\"fleet-server-policy\",\"name\":\"Fleet Server policy\",\"namespace\":\"default\",\"has_fleet_server\":true}'" >/dev/null
  echo "✅ Fleet Server policy created."
else
  echo "✅ Fleet Server policy already exists."
fi

# --- Create Fleet enrollment token ---
echo "🎟️ Creating Fleet enrollment token..."
ENROLLMENT_JSON=$(docker exec "$ES_CONTAINER" bash -c \
  "curl -s -u elastic:\$ELASTIC_PASSWORD -X POST '$KIBANA_URL/api/fleet/enrollment_api_keys' \
   -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
   -d '{\"policy_id\":\"fleet-server-policy\"}'")
ENROLLMENT_TOKEN=$(echo "$ENROLLMENT_JSON" | grep -oP '\"api_key\"\s*:\s*\"\K[^\"]+')
echo "✅ Enrollment token created."

# --- Start Fleet Server container ---
echo "📥 Pulling Fleet Server image..."
docker pull docker.elastic.co/elastic-agent/elastic-agent:"$STACK_VERSION"

echo "🚀 Starting Fleet Server container..."
docker run -d --name fleet-server \
  --net $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' "$ES_CONTAINER") \
  -v elk_certs:/usr/share/elasticsearch/config/certs:ro \
  -e FLEET_SERVER_ENABLE=1 \
  -e FLEET_SERVER_ELASTICSEARCH_HOST="$ES_URL" \
  -e FLEET_SERVER_SERVICE_TOKEN="$SERVICE_TOKEN" \
  -e FLEET_SERVER_ELASTICSEARCH_CA="$CA_PATH" \
  -e FLEET_ENROLL=1 \
  -e FLEET_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
  -e FLEET_URL=https://fleet-server:8220 \
  -p 8220:8220 \
  docker.elastic.co/elastic-agent/elastic-agent:"$STACK_VERSION"

echo "✅ Fleet Server container started."
echo "⏳ Waiting for Fleet Server to be healthy..."
while ! curl -s -k https://localhost:8220/api/status 2>/dev/null | grep -q '"status":"HEALTHY"'; do
  echo "   Fleet Server not ready yet, waiting..."
  sleep 5
done
echo "✅ Fleet Server is healthy!"

# --- Add Fleet Server to docker-compose.yml ---
echo "📝 Adding Fleet Server to docker-compose.yml..."

# Create fleet-server service definition in a temp file
cat > /tmp/fleet-service.yml << 'FLEET_SERVICE_EOF'

  fleet-server:
    container_name: fleet-server
    depends_on:
      es01:
        condition: service_healthy
      kibana:
        condition: service_healthy
    image: docker.elastic.co/elastic-agent/elastic-agent:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs:ro
    ports:
      - 8220:8220
    environment:
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://es01:9200
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_ELASTICSEARCH_CA=/usr/share/elasticsearch/config/certs/ca/ca.crt
      - FLEET_ENROLL=1
      - FLEET_ENROLLMENT_TOKEN=${FLEET_ENROLLMENT_TOKEN}
      - FLEET_URL=https://fleet-server:8220
    mem_limit: ${MEM_LIMIT}
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s -k https://localhost:8220/api/status | grep -q '\"status\":\"HEALTHY\"'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120
FLEET_SERVICE_EOF

# Insert the fleet-server service before the volumes section
awk '/^volumes:/ {system("cat /tmp/fleet-service.yml")} {print}' docker-compose.yml > /tmp/docker-compose-new.yml
mv /tmp/docker-compose-new.yml docker-compose.yml
rm /tmp/fleet-service.yml


# --- Save tokens to .env file ---
echo "💾 Saving Fleet tokens to .env file..."
cat >> .env << ENV_FLEET_EOF

# Fleet Server tokens (auto-generated during setup)
FLEET_SERVICE_TOKEN=${SERVICE_TOKEN}
FLEET_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
ENV_FLEET_EOF

# --- Stop manual container and start via docker compose ---
echo "🔄 Transitioning Fleet Server to docker compose management..."
docker stop fleet-server >/dev/null 2>&1 || true
docker rm fleet-server >/dev/null 2>&1 || true
docker compose up -d fleet-server

echo ""
echo "✅ Fleet Server successfully added to ELK stack!"
echo "   - Fleet Server is now managed by docker compose"
echo "   - Service will persist across docker compose restarts"
echo "   - Access Fleet at: http://localhost:5601/app/fleet"
FLEET_EOF

chmod +x /opt/elk/setup-fleet.sh

msg_ok "Fleet Server setup script created"

msg_info "Creating systemd service for ELK stack"
cat > /etc/systemd/system/elk-stack.service << 'SYSTEMD_ELK_EOF'
[Unit]
Description=Elasticsearch Stack
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/elk
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose restart

[Install]
WantedBy=multi-user.target
SYSTEMD_ELK_EOF

systemctl daemon-reload
systemctl enable elk-stack.service >/dev/null 2>&1

msg_ok "Systemd service created and enabled"

echo -e "\n${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "${GN}  Starting ELK Stack Deployment${CL}"
echo -e "${GN}═══════════════════════════════════════════════════════════${CL}\n"

START_NOW="yes"
FLEET_READY="no"

cd /opt/elk

msg_info "Starting ELK stack (Elasticsearch + Kibana)"
  docker compose up -d
  msg_ok "ELK stack containers started"

  echo -e "\n  ${BL}Waiting for Elasticsearch cluster to be healthy...${CL}"
  echo -e "  ${YW}This may take 2-3 minutes${CL}\n"

  TIMEOUT=300
  ELAPSED=0
  while [ $ELAPSED -lt $TIMEOUT ]; do
    if docker exec es01 curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 2>/dev/null | grep -q "missing authentication credentials"; then
      msg_ok "Elasticsearch cluster is healthy"
      break
    fi
    echo -ne "  ⏳ Waiting... ${ELAPSED}s / ${TIMEOUT}s\r"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
  done

  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "\n"
    msg_error "Elasticsearch did not become healthy in time"
    echo -e "  Check logs: ${YW}cd /opt/elk && docker compose logs es01${CL}\n"
    exit 1
  fi

  echo -e "\n  ${BL}Waiting for Kibana to be ready...${CL}"
  echo -e "  ${YW}This may take 1-2 minutes${CL}\n"

  TIMEOUT=180
  ELAPSED=0
  while [ $ELAPSED -lt $TIMEOUT ]; do
    if docker exec es01 curl -s http://kibana:5601/api/status 2>/dev/null | grep -q '"level":"available"'; then
      msg_ok "Kibana is ready"
      break
    fi
    echo -ne "  ⏳ Waiting... ${ELAPSED}s / ${TIMEOUT}s\r"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
  done

  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo -e "\n"
    msg_error "Kibana did not become ready in time"
    echo -e "  Check logs: ${YW}cd /opt/elk && docker compose logs kibana${CL}\n"
    exit 1
  fi

  # Set up Fleet Server automatically
  echo -e "\n${BL}═══════════════════════════════════════════════════════════${CL}"
  echo -e "${BL}  Setting up Fleet Server${CL}"
  echo -e "${BL}═══════════════════════════════════════════════════════════${CL}\n"

  # Load environment variables
  source .env

  ES_CONTAINER="es01"
  ES_URL="https://es01:9200"
  KIBANA_URL="http://kibana:5601"
  CA_PATH="/usr/share/elasticsearch/config/certs/ca/ca.crt"

  msg_info "Creating Fleet Server service token"
  SERVICE_TOKEN_JSON=$(docker exec "$ES_CONTAINER" bash -c \
    "curl -s -u elastic:\$ELASTIC_PASSWORD --cacert $CA_PATH -X POST '$ES_URL/_security/service/elastic/fleet-server/credential/token'")
  SERVICE_TOKEN=$(echo "$SERVICE_TOKEN_JSON" | grep -oP '"value"\s*:\s*"\K[^"]+')

  if [ -z "$SERVICE_TOKEN" ]; then
    msg_error "Failed to create Fleet Server service token"
    exit 1
  fi
  msg_ok "Fleet Server service token created"

  msg_info "Checking for Fleet Server policy"
  POLICY_JSON=$(docker exec "$ES_CONTAINER" bash -c \
    "curl -s -u elastic:\$ELASTIC_PASSWORD -X GET '$KIBANA_URL/api/fleet/agent_policies' -H 'kbn-xsrf: true'")
  POLICY_EXISTS=$(echo "$POLICY_JSON" | grep -o '"id":"fleet-server-policy"' || true)

  if [ -z "$POLICY_EXISTS" ]; then
    msg_info "Creating Fleet Server agent policy"
    docker exec "$ES_CONTAINER" bash -c \
      "curl -s -u elastic:\$ELASTIC_PASSWORD -X POST '$KIBANA_URL/api/fleet/agent_policies' \
       -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
       -d '{\"id\":\"fleet-server-policy\",\"name\":\"Fleet Server policy\",\"namespace\":\"default\",\"has_fleet_server\":true}'" >/dev/null
    msg_ok "Fleet Server policy created"
  else
    msg_ok "Fleet Server policy already exists"
  fi

  msg_info "Creating Fleet enrollment token"
  ENROLLMENT_JSON=$(docker exec "$ES_CONTAINER" bash -c \
    "curl -s -u elastic:\$ELASTIC_PASSWORD -X POST '$KIBANA_URL/api/fleet/enrollment_api_keys' \
     -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
     -d '{\"policy_id\":\"fleet-server-policy\"}'")
  ENROLLMENT_TOKEN=$(echo "$ENROLLMENT_JSON" | grep -oP '\"api_key\"\s*:\s*\"\K[^\"]+')

  if [ -z "$ENROLLMENT_TOKEN" ]; then
    msg_error "Failed to create Fleet enrollment token"
    exit 1
  fi
  msg_ok "Fleet enrollment token created"

  msg_info "Pulling Fleet Server image"
  docker pull docker.elastic.co/elastic-agent/elastic-agent:"$STACK_VERSION" >/dev/null 2>&1
  msg_ok "Fleet Server image pulled"

  msg_info "Starting Fleet Server container"
  NETWORK_ID=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' "$ES_CONTAINER")
  docker run -d --name fleet-server \
    --net "$NETWORK_ID" \
    -v elk_certs:/usr/share/elasticsearch/config/certs:ro \
    -e FLEET_SERVER_ENABLE=1 \
    -e FLEET_SERVER_ELASTICSEARCH_HOST="$ES_URL" \
    -e FLEET_SERVER_SERVICE_TOKEN="$SERVICE_TOKEN" \
    -e FLEET_SERVER_ELASTICSEARCH_CA="$CA_PATH" \
    -e FLEET_ENROLL=1 \
    -e FLEET_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" \
    -e FLEET_URL=https://fleet-server:8220 \
    -p 8220:8220 \
    docker.elastic.co/elastic-agent/elastic-agent:"$STACK_VERSION" >/dev/null 2>&1
  msg_ok "Fleet Server container started"

  echo -e "\n  ${BL}Waiting for Fleet Server to be healthy...${CL}"
  echo -e "  ${YW}This may take 1-2 minutes${CL}\n"

  TIMEOUT=180
  ELAPSED=0
  while [ $ELAPSED -lt $TIMEOUT ]; do
    if curl -s -k https://localhost:8220/api/status 2>/dev/null | grep -q '"status":"HEALTHY"'; then
      msg_ok "Fleet Server is healthy"
      FLEET_READY="yes"
      break
    fi
    echo -ne "  ⏳ Waiting... ${ELAPSED}s / ${TIMEOUT}s\r"
    sleep 5
    ELAPSED=$((ELAPSED + 5))
  done

  if [ "$FLEET_READY" != "yes" ]; then
    echo -e "\n"
    msg_error "Fleet Server did not become healthy in time"
    echo -e "  Check logs: ${YW}docker logs fleet-server${CL}\n"
  fi

  # Add Fleet Server to docker-compose.yml
  if [ "$FLEET_READY" == "yes" ]; then
    msg_info "Adding Fleet Server to docker-compose.yml"

    # Check if fleet-server already exists in compose file
    if ! grep -q "fleet-server:" docker-compose.yml; then
      # Create fleet-server service definition in a temporary file
      cat > /tmp/fleet-service.yml << 'FLEET_SERVICE_EOF'
  fleet-server:
    container_name: fleet-server
    depends_on:
      es01:
        condition: service_healthy
      kibana:
        condition: service_healthy
    image: docker.elastic.co/elastic-agent/elastic-agent:${STACK_VERSION}
    volumes:
      - certs:/usr/share/elasticsearch/config/certs:ro
    ports:
      - 8220:8220
    environment:
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://es01:9200
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_ELASTICSEARCH_CA=/usr/share/elasticsearch/config/certs/ca/ca.crt
      - FLEET_ENROLL=1
      - FLEET_ENROLLMENT_TOKEN=${FLEET_ENROLLMENT_TOKEN}
      - FLEET_URL=https://fleet-server:8220
    mem_limit: ${MEM_LIMIT}
    restart: unless-stopped
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "curl -s -k https://localhost:8220/api/status | grep -q '\"status\":\"HEALTHY\"'",
        ]
      interval: 10s
      timeout: 10s
      retries: 120

FLEET_SERVICE_EOF

      # Insert the fleet-server service before the volumes section
      awk '/^volumes:/ {system("cat /tmp/fleet-service.yml")} {print}' docker-compose.yml > /tmp/docker-compose-new.yml
      mv /tmp/docker-compose-new.yml docker-compose.yml
      rm /tmp/fleet-service.yml
    fi

    # Save tokens to .env file
    cat >> .env << ENV_FLEET_EOF

# Fleet Server tokens (auto-generated during setup)
FLEET_SERVICE_TOKEN=${SERVICE_TOKEN}
FLEET_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
ENV_FLEET_EOF

    msg_ok "Fleet Server added to docker-compose.yml"

    # Stop manual container and start via docker compose
    msg_info "Transitioning Fleet Server to docker compose management"
    docker stop fleet-server 2>/dev/null
    sleep 2
    docker rm fleet-server 2>/dev/null
    sleep 1
    docker compose up -d fleet-server
    msg_ok "Fleet Server now managed by docker compose"
  fi

# Get IP address
IP_ADDRESS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)

echo -e "\n${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "${GN}  ✅ Elasticsearch Stack Installation Complete!${CL}"
echo -e "${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "  🐋 Docker:       ${GN}Installed with userns-remap${CL}"
echo -e "  🔍 Elasticsearch: ${GN}3-node cluster${CL}"
echo -e "  📊 Kibana:       ${GN}Installed${CL}"
if [ "$FLEET_READY" == "yes" ]; then
  echo -e "  🚀 Fleet Server: ${GN}Installed and running${CL}"
fi
if [ "$START_NOW" == "yes" ]; then
  echo -e "  ▶️  Status:       ${GN}Running${CL}"
else
  echo -e "  ⏸️  Status:       ${YW}Not started${CL}"
fi
echo -e "${GN}═══════════════════════════════════════════════════════════${CL}"
echo -e "\n  ${BL}Elasticsearch Credentials:${CL}"
echo -e "    • Elastic user: ${GN}elastic${CL}"
echo -e "    • Elastic pass: ${GN}${ELASTIC_PASSWORD}${CL}"
echo -e "    • Kibana user:  ${GN}kibana_system${CL}"
echo -e "    • Kibana pass:  ${GN}${KIBANA_PASSWORD}${CL}"
echo -e "\n  ${BL}Access URLs:${CL}"
echo -e "    • Elasticsearch: ${YW}https://${IP_ADDRESS}:9200${CL}"
echo -e "    • Kibana:        ${YW}http://${IP_ADDRESS}:5601${CL}"
if [ "$FLEET_READY" == "yes" ]; then
  echo -e "    • Fleet Server:  ${YW}https://${IP_ADDRESS}:8220${CL}"
fi
echo -e "    • Configuration: ${YW}/opt/elk/${CL}"
echo -e "    • Credentials:   ${YW}/opt/elk/.env${CL}"
echo -e "\n  ${BL}Management Commands:${CL}"
if [ "$START_NOW" != "yes" ]; then
  echo -e "    • Start stack:    ${YW}sudo systemctl start elk-stack${CL}"
fi
echo -e "    • Stop stack:     ${YW}sudo systemctl stop elk-stack${CL}"
echo -e "    • Restart stack:  ${YW}sudo systemctl restart elk-stack${CL}"
echo -e "    • Status:         ${YW}cd /opt/elk && docker compose ps${CL}"
echo -e "    • View logs:      ${YW}cd /opt/elk && docker compose logs -f${CL}"
if [ "$FLEET_READY" != "yes" ] && [ -f "/opt/elk/setup-fleet.sh" ]; then
  echo -e "    • Setup Fleet:    ${YW}cd /opt/elk && ./setup-fleet.sh${CL}"
fi
echo -e "\n  ${BL}System Configuration:${CL}"
echo -e "    • Kernel: vm.max_map_count=262144 (configured)"
echo -e "    • Docker: userns-remap security enabled"
echo -e "    • Auto-start: ELK stack enabled on boot"
echo -e "    • Time sync: systemd-timesyncd active"
echo -e "\n  ${RD}⚠️  IMPORTANT:${CL}"
echo -e "    • Save all passwords securely!"
echo -e "    • Configure firewall for ports 9200 (Elastic), 5601 (Kibana) or setup a reverse proxy."
if [ "$FLEET_READY" == "yes" ]; then
  echo -e "    • Configure firewall for port 8220 (Fleet)"
fi
echo -e ""
