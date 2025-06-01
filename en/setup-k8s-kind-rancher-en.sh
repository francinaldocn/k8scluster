#!/bin/bash
set -euo pipefail

# ==================== CONFIGURATION VARIABLES ====================
CLUSTER_NAME="k8s-cluster"
RANCHER_HOSTNAME="rancher.localhost"
RANCHER_PASSWORD="" # Password will be prompted to the user during execution.
KIND_CONFIG_FILE="kind-cluster.yaml"
CERT_DIR="./certs"

# Tool and Helm Chart Version Definitions
KIND_VERSION="v0.29.0"
RANCHER_CLI_VERSION="v2.11.2"
CERT_MANAGER_CHART_VERSION="v1.15.0" # Check the latest version at https://artifacthub.io/packages/helm/jetstack/cert-manager
RANCHER_MONITORING_CHART_VERSION="103.2.2+up57.0.3" # Validated version for this environment.

# ==================== SYSTEM LOGGING FUNCTIONS ====================

# ANSI color codes
COLOR_RESET='\033[0m'
COLOR_INFO='\033[0;34m'    # Blue
COLOR_SUCCESS='\033[0;32m' # Green
COLOR_WARN='\033[0;33m'    # Yellow
COLOR_ERROR='\033[0;31m'   # Red
COLOR_MENU_TITLE='\033[1;32m' # Bold Green for menu title
COLOR_MENU_OPTION='\033[0;36m' # Cyan for menu options
COLOR_PROMPT='\033[0;37m' # White/Light Gray for prompt

echo_info() { echo -e "${COLOR_INFO}INFO: $*${COLOR_RESET}"; }
echo_success() { echo -e "${COLOR_SUCCESS}SUCCESS: $*${COLOR_RESET}"; }
echo_warn() { echo -e "${COLOR_WARN}WARNING: $*${COLOR_RESET}"; }
echo_error() { echo -e "${COLOR_ERROR}ERROR: $*${COLOR_RESET}" >&2; }

# ==================== PREREQUISITE AND HOST CONFIGURATION FUNCTIONS ====================

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo_warn "Running without root privileges. Some operations may fail or require sudo authentication."
  fi
}

detect_distro() {
  echo_info "Starting Linux distribution detection..."
  # Get OS information from /etc/os-release.
  source /etc/os-release
  DISTRO_ID="${ID,,}"
  DISTRO_ID_LIKE="${ID_LIKE,,}"
  UBUNTU_CODENAME="${UBUNTU_CODENAME:-}"
  VERSION_CODENAME="${VERSION_CODENAME:-}"
  
  # Determine the distribution base (Debian/Ubuntu or RHEL).
  if [[ "$DISTRO_ID" == "linuxmint" ]]; then
    if [[ -n "$UBUNTU_CODENAME" ]]; then
      BASE_CODENAME="$UBUNTU_CODENAME"
    else
      BASE_CODENAME="$VERSION_CODENAME"
    fi
    BASE_DISTRO="ubuntu"
  elif [[ "$DISTRO_ID_LIKE" =~ "ubuntu|debian" ]]; then
    BASE_DISTRO="ubuntu" # Used as base for Docker installation via APT.
    BASE_CODENAME="$VERSION_CODENAME"
  elif [[ "$DISTRO_ID_LIKE" =~ "rhel|fedora|centos" || "$DISTRO_ID" == "fedora" || "$DISTRO_ID" == "centos" || "$DISTRO_ID" == "rocky" || "$DISTRO_ID" == "almalinux" ]]; then
    BASE_DISTRO="rhel"
  else
    echo_error "Unsupported Linux distribution: $DISTRO_ID"
    exit 1
  fi
  
  echo_info "Detected distribution: $DISTRO_ID"
  echo_info "OS base: $BASE_DISTRO"
  [[ -n "$BASE_CODENAME" ]] && echo_info "Base codename (Ubuntu/Debian): $BASE_CODENAME"
}

install_docker() {
  echo_info "Starting Docker installation procedure..."

  if command -v docker &>/dev/null; then
    echo_success "Docker is already installed."
    return
  fi

  if [[ "$BASE_DISTRO" == "ubuntu" ]]; then
    # Prepare the environment for Docker installation on Debian/Ubuntu-based systems.
    sudo apt-get update
    if [ $? -ne 0 ]; then echo_error "Failed to update APT packages."; exit 1; fi
    sudo apt-get install -y ca-certificates curl gnupg lsb-release
    if [ $? -ne 0 ]; then echo_error "Failed to install Docker dependencies (APT)."; exit 1; fi

    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    if [ $? -ne 0 ]; then echo_error "Failed to download Docker GPG key."; exit 1; fi

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $BASE_CODENAME stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    if [ $? -ne 0 ]; then echo_error "Failed to add Docker repository."; exit 1; fi

    sudo apt-get update
    if [ $? -ne 0 ]; then echo_error "Failed to update APT packages after adding Docker repository."; exit 1; fi
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    if [ $? -ne 0 ]; then echo_error "Failed to install Docker packages (APT)."; exit 1; fi

  elif [[ "$BASE_DISTRO" == "rhel" ]]; then
    # Detect the appropriate package manager (dnf or yum) for RHEL systems.
    if command -v dnf &>/dev/null; then
      PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
      PKG_MANAGER="yum"
    else
      echo_error "No package manager (dnf or yum) found for RHEL systems."
      exit 1
    fi

    sudo "$PKG_MANAGER" install -y yum-utils
    if [ $? -ne 0 ]; then echo_error "Failed to install yum-utils."; exit 1; fi
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    if [ $? -ne 0 ]; then echo_error "Failed to add Docker repository (RHEL)."; exit 1; fi
    sudo "$PKG_MANAGER" install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    if [ $? -ne 0 ]; then echo_error "Failed to install Docker packages (RHEL)."; exit 1; fi
  fi

  sudo systemctl enable --now docker
  if [ $? -ne 0 ]; then echo_error "Failed to enable/start Docker service."; exit 1; fi

  # Adjust Docker access permissions for the current user.
  echo_info "Adjusting Docker group permissions..."
  if groups "$USER" | grep -qw docker; then
    echo_success "User $USER already belongs to the docker group."
  else
    echo_info "Adding user $USER to the docker group..."
    sudo usermod -aG docker "$USER"
    if [ $? -ne 0 ]; then echo_error "Failed to add user to docker group."; exit 1; fi
    echo_warn "User $USER has been added to the docker group. Please log out/log in or restart your terminal for permissions to apply."
    echo_warn "Press Enter to continue (note the need to restart the terminal to apply permissions)."
    read -r
  fi

  echo_success "Docker installed and running."
}

install_kubectl() {
  echo_info "Starting kubectl installation procedure..."

  if command -v kubectl &>/dev/null; then
    echo_success "kubectl is already installed."
    return
  fi

  curl -fsSL https://dl.k8s.io/release/stable.txt | xargs -I {} curl -fsSL -o kubectl https://dl.k8s.io/release/{}/bin/linux/amd64/kubectl
  if [ $? -ne 0 ]; then echo_error "Failed to download kubectl binary."; exit 1; fi
  sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  if [ $? -ne 0 ]; then echo_error "Failed to install kubectl."; exit 1; fi
  rm kubectl

  echo_success "kubectl installed."
}

install_helm() {
  echo_info "Starting Helm installation procedure..."

  if command -v helm &>/dev/null; then
    echo_success "Helm is already installed."
    return
  fi

  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  if [ $? -ne 0 ]; then echo_error "Failed to install Helm."; exit 1; fi

  echo_success "Helm installed."
}

install_kind() {
  echo_info "Starting Kind installation procedure..."

  if command -v kind &>/dev/null; then
    echo_success "Kind is already installed."
    return
  fi

  curl -fsSL -o kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
  if [ $? -ne 0 ]; then echo_error "Failed to download Kind binary."; exit 1; fi
  chmod +x kind
  sudo mv kind /usr/local/bin/kind
  if [ $? -ne 0 ]; then echo_error "Failed to install Kind."; exit 1; fi

  echo_success "Kind installed."
}

install_rancher_cli() {
  echo_info "Starting Rancher CLI installation procedure..."

  if command -v rancher &>/dev/null; then
    echo_success "Rancher CLI is already installed."
    return
  fi

  ARCH="amd64" # Standard architecture
  URL="https://github.com/rancher/cli/releases/download/${RANCHER_CLI_VERSION}/rancher-linux-${ARCH}-${RANCHER_CLI_VERSION}.tar.gz"

  curl -fsSL -o rancher-cli.tar.gz "$URL"
  if [ $? -ne 0 ]; then echo_error "Failed to download Rancher CLI."; exit 1; fi
  tar -xzvf rancher-cli.tar.gz
  if [ $? -ne 0 ]; then echo_error "Failed to extract Rancher CLI."; exit 1; fi
  sudo mv rancher-"${RANCHER_CLI_VERSION}"/rancher /usr/local/bin/
  if [ $? -ne 0 ]; then echo_error "Failed to install Rancher CLI."; exit 1; fi
  rm -rf rancher-"${RANCHER_CLI_VERSION}" rancher-cli.tar.gz

  echo_success "Rancher CLI installed."
}

configure_sysctl() {
  echo_info "Configuring system parameters (sysctl)..."
  SYSCTL_FILE="/etc/sysctl.d/99-k8s.conf"
  sudo tee "$SYSCTL_FILE" > /dev/null <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
EOF
  if [ $? -ne 0 ]; then echo_error "Failed to create sysctl file."; exit 1; fi
  sudo sysctl --system
  if [ $? -ne 0 ]; then echo_error "Failed to apply sysctl configurations."; exit 1; fi
  echo_success "Sysctl parameters configured."
}

configure_docker_systemd() {
  echo_info "Adjusting systemd configuration for Docker service (increasing limits)..."
  OVERRIDE_DIR="/etc/systemd/system/docker.service.d"
  OVERRIDE_FILE="$OVERRIDE_DIR/override.conf"

  sudo mkdir -p "$OVERRIDE_DIR"
  if [ $? -ne 0 ]; then echo_error "Failed to create Docker systemd override directory."; exit 1; fi
  sudo tee "$OVERRIDE_FILE" > /dev/null <<EOF
[Service]
LimitNOFILE=1048576
EOF
  if [ $? -ne 0 ]; then echo_error "Failed to create Docker systemd override file."; exit 1; fi

  sudo systemctl daemon-reload
  if [ $? -ne 0 ]; then echo_error "Failed to reload systemd daemon."; exit 1; fi
  sudo systemctl restart docker
  if [ $? -ne 0 ]; then echo_error "Failed to restart Docker service."; exit 1; fi
  echo_success "Docker systemd configuration applied."
}

# ==================== KUBERNETES AND RANCHER FUNCTIONS ====================

check_cluster_connection() {
  echo_info "Checking Kubernetes cluster connectivity..."
  kubectl cluster-info &>/dev/null
  if [ $? -ne 0 ]; then
    echo_error "Failed to connect to Kubernetes cluster. Ensure Kind is running and kubeconfig is correctly configured."
    echo_info "To check if the cluster exists, run 'kind get clusters'."
    exit 1
  fi
  echo_success "Kubernetes cluster connection established."
}

create_kind_cluster() {
  echo_info "Generating Kind configuration file..."

cat <<EOF > "$KIND_CONFIG_FILE"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 80
        protocol: TCP
      - containerPort: 30443
        hostPort: 443
        protocol: TCP
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            allowed-unsafe-sysctls: "net.ipv6.conf.all.disable_ipv6,net.ipv6.conf.default.disable_ipv6"
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            allowed-unsafe-sysctls: "net.ipv6.conf.all.disable_ipv6,net.ipv6.conf.default.disable_ipv6"
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            allowed-unsafe-sysctls: "net.ipv6.conf.all.disable_ipv6,net.ipv6.conf.default.disable_ipv6"
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            allowed-unsafe-sysctls: "net.ipv6.conf.all.disable_ipv6,net.ipv6.conf.default.disable_ipv6"
EOF
  if [ $? -ne 0 ]; then echo_error "Failed to create Kind configuration file."; exit 1; fi

  # Check if the cluster already exists
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    echo_warn "The Kind cluster '$CLUSTER_NAME' already exists."
    echo_warn "Do you want to reinstall it (delete and recreate) or continue with the existing cluster?"
    echo_warn "  [r] Reinstall (delete and recreate)"
    echo_warn "  [c] Continue with the existing cluster"
    echo_warn "  [x] Exit"
    
    local choice
    while true; do
      printf "${COLOR_PROMPT}Choose an option (r/c/x): ${COLOR_RESET}"
      read -r choice
      case "$choice" in
        [rR])
          echo_info "Reinstalling cluster '$CLUSTER_NAME'..."
          remove_kind_cluster # Call the function to remove the cluster
          break
          ;;
        [cC])
          echo_info "Continuing with existing cluster '$CLUSTER_NAME'."
          echo_success "Kind cluster is ready for use."
          return # Exit the function, do not attempt to create the cluster
          ;;
        [xX])
          echo_info "Operation canceled. Exiting."
          exit 0
          ;;
        *)
          echo_error "Invalid option. Please choose 'r' to reinstall, 'c' to continue, or 'x' to exit."
          ;;
      esac
    done
  fi

  echo_info "Creating Kind cluster ($CLUSTER_NAME)... This process may take several minutes."
  kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG_FILE"
  if [ $? -ne 0 ]; then echo_error "Failed to create Kind cluster."; exit 1; fi

  echo_info "🔧 Disabling automatic restart for Kind containers..."
  for container in $(docker ps -a --filter name="$CLUSTER_NAME" --format "{{.Names}}"); do
    docker update --restart=no "$container"
  done

  echo_success "✅ Kind cluster created and configured with restart='no'."
}

start_kind_cluster() {
  echo_info "Starting Kind cluster ($CLUSTER_NAME)..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    # Kind clusters are composed of Docker containers. The 'docker start' command is used to start them.
    local containers=$(docker ps -a --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --format "{{.Names}}")
    if [[ -n "$containers" ]]; then
      echo_info "Starting Docker containers for Kind cluster: $containers"
      docker start $containers
      if [ $? -ne 0 ]; then echo_error "Failed to start Kind cluster containers."; exit 1; fi
      echo_success "Kind cluster '$CLUSTER_NAME' started."
      # Wait for kubectl connectivity to ensure the cluster is operational.
      echo_info "Waiting for Kind cluster to be ready to accept kubectl connections..."
      local start_time=$(date +%s)
      local timeout=120 # 2-minute timeout
      while ! kubectl cluster-info &>/dev/null; do
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [[ $elapsed_time -ge $timeout ]]; then
          echo_error "Timeout while waiting for Kind cluster to be ready."
          exit 1
        fi
        echo_info "Waiting for kubectl connection... ($elapsed_time/${timeout}s)"
        sleep 5
      done
      echo_success "Kind cluster ready for use."
    else
      echo_warn "No Docker containers found for Kind cluster '$CLUSTER_NAME'. The cluster may not exist or is already running."
    fi
  else
    echo_warn "No Kind cluster named '$CLUSTER_NAME' found. Please create the cluster first."
  fi
}

stop_kind_cluster() {
  echo_info "Stopping Kind cluster ($CLUSTER_NAME)..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    # Kind clusters are composed of Docker containers. The 'docker stop' command is used to stop them.
    local containers=$(docker ps --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --format "{{.Names}}")
    if [[ -n "$containers" ]]; then
      echo_info "Stopping Docker containers for Kind cluster: $containers"
      docker stop $containers
      if [ $? -ne 0 ]; then echo_error "Failed to stop Kind cluster containers."; exit 1; fi
      echo_success "Kind cluster '$CLUSTER_NAME' stopped."
    else
      echo_warn "No running Docker containers found for Kind cluster '$CLUSTER_NAME'. The cluster may already be stopped or does not exist."
    fi
  else
    echo_warn "No Kind cluster named '$CLUSTER_NAME' found."
  fi
}

install_nginx_ingress() {
  check_cluster_connection
  echo_info "Starting NGINX Ingress Controller installation via Helm..."

  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
  if [ $? -ne 0 ]; then echo_error "Failed to add 'ingress-nginx' Helm repository."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Failed to update Helm repositories."; exit 1; fi

  helm upgrade --install nginx-ingress ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.ingressClassResource.name=nginx \
  --set controller.ingressClassResource.default=true \
  --set controller.service.type=NodePort \
  --set controller.service.nodePorts.http=30080 \
  --set controller.service.nodePorts.https=30443 \
  --set controller.minReadySeconds=5 \
  --set controller.progressDeadlineSeconds=60 \
  --wait --timeout 10m # Wait for installation to complete with a timeout.

  if [ $? -ne 0 ]; then echo_error "Failed to install NGINX Ingress Controller."; exit 1; fi
  echo_success "NGINX Ingress Controller installed."
}

install_cert_manager() {
  check_cluster_connection
  echo_info "Starting cert-manager installation via Helm..."

  helm repo add jetstack https://charts.jetstack.io
  if [ $? -ne 0 ]; then echo_error "Failed to add 'jetstack' Helm repository."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Failed to update Helm repositories."; exit 1; fi

  helm upgrade --install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace \
    --set installCRDs=true \
    --version "${CERT_MANAGER_CHART_VERSION}" \
    --wait --timeout 10m # Wait for installation to complete with a timeout.

  if [ $? -ne 0 ]; then echo_error "Failed to install cert-manager."; exit 1; fi
  echo_success "cert-manager installed."
}

create_rancher_cert() {
  check_cluster_connection
  echo_info "Creating self-signed certificate for Rancher..."

  mkdir -p "$CERT_DIR"
  if [ $? -ne 0 ]; then echo_error "Failed to create certificates directory."; exit 1; fi

  cat <<EOF > "$CERT_DIR/openssl.cnf"
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[ req_distinguished_name ]
CN = $RANCHER_HOSTNAME

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $RANCHER_HOSTNAME
EOF
  if [ $? -ne 0 ]; then echo_error "Failed to create openssl.cnf file."; exit 1; fi

  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" -config "$CERT_DIR/openssl.cnf"
  if [ $? -ne 0 ]; then echo_error "Failed to generate TLS certificate."; exit 1; fi

  # Set restrictive permissions for the private key.
  chmod 600 "$CERT_DIR/tls.key"
  if [ $? -ne 0 ]; then echo_error "Failed to set permissions for tls.key."; exit 1; fi
  chmod 644 "$CERT_DIR/tls.crt"
  if [ $? -ne 0 ]; then echo_error "Failed to set permissions for tls.crt."; exit 1; fi
  
  kubectl create namespace cattle-system --dry-run=client -o yaml | kubectl apply -f -
  if [ $? -ne 0 ]; then echo_error "Failed to create 'cattle-system' namespace."; exit 1; fi

  kubectl -n cattle-system delete secret tls-ca --ignore-not-found
  # Error checking is not necessary here, as '--ignore-not-found' handles the absence of the secret.

  kubectl -n cattle-system create secret generic tls-ca \
    --from-file=cacerts.pem="$CERT_DIR/tls.crt"
  if [ $? -ne 0 ]; then echo_error "Failed to create 'tls-ca' secret."; exit 1; fi

  echo_success "Rancher TLS certificate created and applied."
}

install_rancher_server() {
  check_cluster_connection
  echo_info "Starting Rancher Server installation via Helm... This process may take several minutes."

  # Prompt for Rancher bootstrap password, with length validation.
  RANCHER_PASSWORD="" # Ensure the variable is empty at the start of the loop.
  while [[ ${#RANCHER_PASSWORD} -lt 12 ]]; do
    if [[ -n "$RANCHER_PASSWORD" ]]; then # Display error only if a password was entered and is invalid
      echo_error "Password must contain at least 12 characters."
    fi
    echo_info "Please set a password for the 'admin' user of Rancher."
    read -s -p "Enter Rancher password (minimum 12 characters): " RANCHER_PASSWORD
    echo # Add a new line after password input.
  done

  helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
  if [ $? -ne 0 ]; then echo_error "Failed to add 'rancher-latest' Helm repository."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Failed to update Helm repositories."; exit 1; fi

  helm upgrade --install rancher rancher-latest/rancher \
    --namespace cattle-system \
    --set hostname="$RANCHER_HOSTNAME" \
    --set bootstrapPassword="$RANCHER_PASSWORD" \
    --set ingress.ingressClassName=nginx \
    --set ingress.tls.source=secret \
    --set ingress.tls.secretName=tls-ca \
    --set privateCA=true \
    --set replicas=1 \
    --wait --timeout 600s # Wait for installation to complete with a timeout.

  if [ $? -ne 0 ]; then echo_error "Failed to install Rancher Server."; exit 1; fi
  echo_success "Rancher Server installed."
}

install_monitoring() {
  check_cluster_connection
  echo_info "Starting Monitoring (Prometheus + Grafana) installation in the cluster... This process may take several minutes."

  # Add Rancher charts repository.
  helm repo add rancher-charts https://charts.rancher.io || true # Allows the command not to fail if the repository already exists.
  if [ $? -ne 0 ]; then echo_error "Failed to add 'rancher-charts' Helm repository."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Failed to update Helm repositories."; exit 1; fi

  # Install mandatory Custom Resource Definitions (CRDs).
  helm upgrade --install rancher-monitoring-crd rancher-charts/rancher-monitoring-crd \
  -n cattle-monitoring-system --create-namespace \
  --version "${RANCHER_MONITORING_CHART_VERSION}" --wait --timeout 5m
  if [ $? -ne 0 ]; then echo_error "Failed to install Rancher Monitoring CRDs."; exit 1; fi

  # Install the monitoring module with a fixed version.
  helm upgrade --install rancher-monitoring rancher-charts/rancher-monitoring \
  -n cattle-monitoring-system --wait \
  --timeout 10m \
  --version "${RANCHER_MONITORING_CHART_VERSION}" \
  --set patch.enabled=true \
  --set prometheus.prometheusSpec.retention=10d \
  --set prometheus.prometheusSpec.resources.requests.memory=750Mi \
  --set prometheus.prometheusSpec.resources.requests.cpu=750m \
  --set prometheus.prometheusSpec.maximumStartupDurationSeconds=300 \
  --set alertmanager.config.useExistingSecret=true \
  --set alertmanager.config.configSecret=alertmanager-rancher-monitoring-alertmanager \
  --set grafana.resources.requests.memory=200Mi \
  --set grafana.resources.requests.cpu=100m \
  --set grafana.ingress.enabled=false \
  --set grafana.service.type=ClusterIP \
  --set grafana.adminPassword=prom-operator \
  --set grafana.ini.security.allow_embedding=true \
  --set grafana.ini.auth.anonymous.enabled=true
  if [ $? -ne 0 ]; then echo_error "Failed to install Rancher Monitoring."; exit 1; fi

  echo_success "Monitoring module installed successfully in the cattle-monitoring-system namespace."
}

install_metrics_server() {
  check_cluster_connection
  echo_info "Starting Metrics Server installation in the cluster..."

  # Add metrics-server repository, ignoring errors if it already exists.
  helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/ || true
  if [ $? -ne 0 ]; then echo_error "Failed to add 'metrics-server' Helm repository."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Failed to update Helm repositories."; exit 1; fi

  # Check for the existence of the kube-system namespace.
  if ! kubectl get namespace kube-system &>/dev/null; then
    echo_info "kube-system namespace not found. Creating..."
    kubectl create namespace kube-system
    if [ $? -ne 0 ]; then echo_error "Failed to create 'kube-system' namespace."; exit 1; fi
  fi

  # Install or update metrics-server via Helm.
  helm upgrade --install metrics-server metrics-server/metrics-server \
    -n kube-system \
    --wait --timeout 5m \
    --set args[0]=--kubelet-insecure-tls \
    --set args[1]=--kubelet-preferred-address-types=InternalIP

  if [ $? -eq 0 ]; then
    echo_success "Metrics Server installed successfully in the kube-system namespace."
  else
    echo_error "Failed to install Metrics Server."
    exit 1
  fi
}


configure_hosts() {
  echo_info "Configuring /etc/hosts file..."
  if ! grep -q "$RANCHER_HOSTNAME" /etc/hosts; then
    echo "127.0.0.1 $RANCHER_HOSTNAME" | sudo tee -a /etc/hosts
    if [ $? -ne 0 ]; then echo_error "Failed to adjust /etc/hosts file."; exit 1; fi
    echo_success "/etc/hosts file adjusted to access $RANCHER_HOSTNAME"
  else
    echo_success "/etc/hosts file already contains the entry for $RANCHER_HOSTNAME."
  fi
}

# ==================== CLEANUP FUNCTIONS ====================

remove_kind_cluster() {
  echo_info "Starting Kind cluster removal..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    read -p "Confirm removal of Kind cluster '$CLUSTER_NAME'? (y/N): " confirm
    if [[ "$confirm" == [yY] ]]; then
      kind delete cluster --name "$CLUSTER_NAME"
      if [ $? -ne 0 ]; then echo_error "Failed to remove Kind cluster."; exit 1; fi
      echo_success "Kind cluster '$CLUSTER_NAME' removed successfully."
    else
      echo_info "Kind cluster removal operation canceled."
    fi
  else
    echo_warn "No Kind cluster named '$CLUSTER_NAME' found."
  fi
}

cleanup_local_files() {
  echo_info "Removing local configuration files and certificates..."
  if [ -f "$KIND_CONFIG_FILE" ]; then
    rm "$KIND_CONFIG_FILE"
    echo_info "Kind configuration file removed: $KIND_CONFIG_FILE"
  fi
  if [ -d "$CERT_DIR" ]; then
    rm -rf "$CERT_DIR"
    echo_info "Certificates directory removed: $CERT_DIR"
  fi
  echo_success "Local file cleanup completed."
}

# ==================== MAIN EXECUTION ====================
show_menu() {
  echo ""
  echo -e "${COLOR_MENU_TITLE}Select the step to execute:${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}1) Install Docker${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}2) Configure Docker (Systemd)${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}3) Configure Sysctl${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}4) Install kubectl${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}5) Install Helm${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}6) Install Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}7) Install Rancher CLI${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}8) Create Kind Cluster${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}9) Install NGINX Ingress${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}10) Install cert-manager${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}11) Generate Rancher certificate${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}12) Install Rancher Server${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}13) Configure /etc/hosts${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}14) Install Monitoring${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}15) Install Metrics Server${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}16) Execute ALL installation steps${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}17) Remove Kind Cluster${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}18) Clean up local files (config, certs)${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}19) Start Kind Cluster${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}20) Stop Kind Cluster${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}0) Exit${COLOR_RESET}"
  printf "${COLOR_PROMPT}Choose an option: ${COLOR_RESET}"
}

main() {
  check_root
  detect_distro

  while true; do
    show_menu
    read -r option
    case $option in
      1) install_docker ;;
      2) configure_docker_systemd ;;
      3) configure_sysctl ;;
      4) install_kubectl ;;
      5) install_helm ;;
      6) install_kind ;;
      7) install_rancher_cli ;;
      8) create_kind_cluster ;;
      9) install_nginx_ingress ;;
      10) install_cert_manager ;;
      11) create_rancher_cert ;;
      12) install_rancher_server ;;
      13) configure_hosts ;;
      14) install_monitoring ;;
      15) install_metrics_server ;;
      16)
        echo_info "Executing ALL environment installation steps..."
        install_docker
        configure_docker_systemd
        configure_sysctl
        install_kubectl
        install_helm
        install_kind
        install_rancher_cli
        create_kind_cluster
        install_nginx_ingress
        install_cert_manager
        create_rancher_cert
        install_rancher_server
        configure_hosts
        install_monitoring
        install_metrics_server
        echo_success "All installation steps completed successfully!"
        echo_success "Rancher is accessible at: https://$RANCHER_HOSTNAME"
        echo_warn "If the user was added to the 'docker' group, a logout/login or terminal restart is required to apply permissions."
        ;;
      17) remove_kind_cluster ;;
      18) cleanup_local_files ;;
      19) start_kind_cluster ;;
      20) stop_kind_cluster ;;
      0) 
        echo_success "Script exiting. Operation completed."
        exit 0
        ;;
      *) 
        echo_warn "Invalid option. Please try again."
        ;;
    esac
    echo "" # Adds a blank line for better menu readability.
  done
}

main
