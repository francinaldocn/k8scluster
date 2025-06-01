#!/bin/bash
set -euo pipefail

# ==================== VARIÁVEIS DE CONFIGURAÇÃO ====================
CLUSTER_NAME="k8s-cluster"
RANCHER_HOSTNAME="rancher.localhost"
RANCHER_PASSWORD="" # A senha será solicitada ao usuário durante a execução.
KIND_CONFIG_FILE="kind-cluster.yaml"
CERT_DIR="./certs"

# Definições de Versões de Ferramentas e Charts Helm
KIND_VERSION="v0.29.0"
RANCHER_CLI_VERSION="v2.11.2"
CERT_MANAGER_CHART_VERSION="v1.15.0" # Verifique a versão mais recente em https://artifacthub.io/packages/helm/jetstack/cert-manager
RANCHER_MONITORING_CHART_VERSION="103.2.2+up57.0.3" # Versão validada para este ambiente.

# ==================== FUNÇÕES DE LOG DO SISTEMA ====================

# Códigos de cores ANSI
COLOR_RESET='\033[0m'
COLOR_INFO='\033[0;34m'    # Azul
COLOR_SUCCESS='\033[0;32m' # Verde
COLOR_WARN='\033[0;33m'    # Amarelo
COLOR_ERROR='\033[0;31m'   # Vermelho
COLOR_MENU_TITLE='\033[1;32m' # Verde negrito para o título do menu
COLOR_MENU_OPTION='\033[0;36m' # Ciano para as opções do menu
COLOR_PROMPT='\033[0;37m' # Branco/Cinza claro para o prompt de escolha

echo_info() { echo -e "${COLOR_INFO}INFO: $*${COLOR_RESET}"; }
echo_success() { echo -e "${COLOR_SUCCESS}SUCESSO: $*${COLOR_RESET}"; }
echo_warn() { echo -e "${COLOR_WARN}AVISO: $*${COLOR_RESET}"; }
echo_error() { echo -e "${COLOR_ERROR}ERRO: $*${COLOR_RESET}" >&2; }

# ==================== FUNÇÕES DE PRÉ-REQUISITOS E CONFIGURAÇÃO DO HOST ====================

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo_warn "Execução sem privilégios de root. Algumas operações podem falhar ou requerer autenticação sudo."
  fi
}

detect_distro() {
  echo_info "Iniciando detecção da distribuição Linux..."
  # Obtém informações do sistema operacional a partir de /etc/os-release.
  source /etc/os-release
  DISTRO_ID="${ID,,}"
  DISTRO_ID_LIKE="${ID_LIKE,,}"
  UBUNTU_CODENAME="${UBUNTU_CODENAME:-}"
  VERSION_CODENAME="${VERSION_CODENAME:-}"
  
  # Determina a base da distribuição (Debian/Ubuntu ou RHEL).
  if [[ "$DISTRO_ID" == "linuxmint" ]]; then
    if [[ -n "$UBUNTU_CODENAME" ]]; then
      BASE_CODENAME="$UBUNTU_CODENAME"
    else
      BASE_CODENAME="$VERSION_CODENAME"
    fi
    BASE_DISTRO="ubuntu"
  elif [[ "$DISTRO_ID_LIKE" =~ "ubuntu|debian" ]]; then
    BASE_DISTRO="ubuntu" # Utilizado como base para instalação do Docker via APT.
    BASE_CODENAME="$VERSION_CODENAME"
  elif [[ "$DISTRO_ID_LIKE" =~ "rhel|fedora|centos" || "$DISTRO_ID" == "fedora" || "$DISTRO_ID" == "centos" || "$DISTRO_ID" == "rocky" || "$DISTRO_ID" == "almalinux" ]]; then
    BASE_DISTRO="rhel"
  else
    echo_error "Distribuição Linux não suportada: $DISTRO_ID"
    exit 1
  fi
  
  echo_info "Distribuição detectada: $DISTRO_ID"
  echo_info "Base do sistema operacional: $BASE_DISTRO"
  [[ -n "$BASE_CODENAME" ]] && echo_info "Codename base (Ubuntu/Debian): $BASE_CODENAME"
}

install_docker() {
  echo_info "Iniciando procedimento de instalação do Docker..."

  if command -v docker &>/dev/null; then
    echo_success "Docker já está instalado."
    return
  fi

  if [[ "$BASE_DISTRO" == "ubuntu" ]]; then
    # Prepara o ambiente para instalação do Docker em sistemas baseados em Debian/Ubuntu.
    sudo apt-get update
    if [ $? -ne 0 ]; then echo_error "Falha na atualização dos pacotes APT."; exit 1; fi
    sudo apt-get install -y ca-certificates curl gnupg lsb-release
    if [ $? -ne 0 ]; then echo_error "Falha na instalação de dependências do Docker (APT)."; exit 1; fi

    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    if [ $? -ne 0 ]; then echo_error "Falha ao baixar a chave GPG do Docker."; exit 1; fi

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $BASE_CODENAME stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório do Docker."; exit 1; fi

    sudo apt-get update
    if [ $? -ne 0 ]; then echo_error "Falha na atualização dos pacotes APT após adicionar o repositório Docker."; exit 1; fi
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    if [ $? -ne 0 ]; then echo_error "Falha na instalação dos pacotes Docker (APT)."; exit 1; fi

  elif [[ "$BASE_DISTRO" == "rhel" ]]; then
    # Detecta o gerenciador de pacotes apropriado (dnf ou yum) para sistemas RHEL.
    if command -v dnf &>/dev/null; then
      PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
      PKG_MANAGER="yum"
    else
      echo_error "Nenhum gerenciador de pacotes (dnf ou yum) encontrado para sistemas RHEL."
      exit 1
    fi

    sudo "$PKG_MANAGER" install -y yum-utils
    if [ $? -ne 0 ]; then echo_error "Falha na instalação de yum-utils."; exit 1; fi
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Docker (RHEL)."; exit 1; fi
    sudo "$PKG_MANAGER" install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    if [ $? -ne 0 ]; then echo_error "Falha na instalação dos pacotes Docker (RHEL)."; exit 1; fi
  fi

  sudo systemctl enable --now docker
  if [ $? -ne 0 ]; then echo_error "Falha ao habilitar/iniciar o serviço Docker."; exit 1; fi

  # Ajusta as permissões de acesso ao Docker para o usuário atual.
  echo_info "Ajustando permissões de grupo do Docker..."
  if groups "$USER" | grep -qw docker; then
    echo_success "O usuário $USER já pertence ao grupo docker."
  else
    echo_info "Adicionando o usuário $USER ao grupo docker..."
    sudo usermod -aG docker "$USER"
    if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o usuário ao grupo docker."; exit 1; fi
    echo_warn "O usuário $USER foi adicionado ao grupo docker. Por favor, faça logout/login ou reinicie o terminal para que as permissões sejam aplicadas."
    echo_warn "Pressione Enter para continuar (observe a necessidade de reiniciar o terminal para aplicar as permissões)."
    read -r
  fi

  echo_success "Docker instalado e em execução."
}

install_kubectl() {
  echo_info "Iniciando procedimento de instalação do kubectl..."

  if command -v kubectl &>/dev/null; then
    echo_success "kubectl já está instalado."
    return
  fi

  curl -fsSL https://dl.k8s.io/release/stable.txt | xargs -I {} curl -fsSL -o kubectl https://dl.k8s.io/release/{}/bin/linux/amd64/kubectl
  if [ $? -ne 0 ]; then echo_error "Falha ao baixar o binário kubectl."; exit 1; fi
  sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  if [ $? -ne 0 ]; then echo_error "Falha ao instalar kubectl."; exit 1; fi
  rm kubectl

  echo_success "kubectl instalado."
}

install_helm() {
  echo_info "Iniciando procedimento de instalação do Helm..."

  if command -v helm &>/dev/null; then
    echo_success "Helm já está instalado."
    return
  fi

  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  if [ $? -ne 0 ]; then echo_error "Falha ao instalar Helm."; exit 1; fi

  echo_success "Helm instalado."
}

install_kind() {
  echo_info "Iniciando procedimento de instalação do Kind..."

  if command -v kind &>/dev/null; then
    echo_success "Kind já está instalado."
    return
  fi

  curl -fsSL -o kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
  if [ $? -ne 0 ]; then echo_error "Falha ao baixar o binário Kind."; exit 1; fi
  chmod +x kind
  sudo mv kind /usr/local/bin/kind
  if [ $? -ne 0 ]; then echo_error "Falha ao instalar Kind."; exit 1; fi

  echo_success "Kind instalado."
}

install_rancher_cli() {
  echo_info "Iniciando procedimento de instalação do Rancher CLI..."

  if command -v rancher &>/dev/null; then
    echo_success "Rancher CLI já está instalado."
    return
  fi

  ARCH="amd64" # Arquitetura padrão
  URL="https://github.com/rancher/cli/releases/download/${RANCHER_CLI_VERSION}/rancher-linux-${ARCH}-${RANCHER_CLI_VERSION}.tar.gz"

  curl -fsSL -o rancher-cli.tar.gz "$URL"
  if [ $? -ne 0 ]; then echo_error "Falha ao baixar o Rancher CLI."; exit 1; fi
  tar -xzvf rancher-cli.tar.gz
  if [ $? -ne 0 ]; then echo_error "Falha ao extrair o Rancher CLI."; exit 1; fi
  sudo mv rancher-"${RANCHER_CLI_VERSION}"/rancher /usr/local/bin/
  if [ $? -ne 0 ]; then echo_error "Falha ao instalar o Rancher CLI."; exit 1; fi
  rm -rf rancher-"${RANCHER_CLI_VERSION}" rancher-cli.tar.gz

  echo_success "Rancher CLI instalado."
}

configure_sysctl() {
  echo_info "Configurando parâmetros do sistema (sysctl)..."
  SYSCTL_FILE="/etc/sysctl.d/99-k8s.conf"
  sudo tee "$SYSCTL_FILE" > /dev/null <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
EOF
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o arquivo sysctl."; exit 1; fi
  sudo sysctl --system
  if [ $? -ne 0 ]; then echo_error "Falha ao aplicar as configurações sysctl."; exit 1; fi
  echo_success "Parâmetros sysctl configurados."
}

configure_docker_systemd() {
  echo_info "Ajustando configuração do systemd para o serviço Docker (aumentando limites)..."
  OVERRIDE_DIR="/etc/systemd/system/docker.service.d"
  OVERRIDE_FILE="$OVERRIDE_DIR/override.conf"

  sudo mkdir -p "$OVERRIDE_DIR"
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o diretório de override do Docker systemd."; exit 1; fi
  sudo tee "$OVERRIDE_FILE" > /dev/null <<EOF
[Service]
LimitNOFILE=1048576
EOF
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o arquivo de override do Docker systemd."; exit 1; fi

  sudo systemctl daemon-reload
  if [ $? -ne 0 ]; then echo_error "Falha ao recarregar o daemon do systemd."; exit 1; fi
  sudo systemctl restart docker
  if [ $? -ne 0 ]; then echo_error "Falha ao reiniciar o serviço Docker."; exit 1; fi
  echo_success "Configuração do Docker systemd aplicada."
}

# ==================== FUNÇÕES DO KUBERNETES E RANCHER ====================

check_cluster_connection() {
  echo_info "Verificando a conectividade com o cluster Kubernetes..."
  kubectl cluster-info &>/dev/null
  if [ $? -ne 0 ]; then
    echo_error "Falha ao conectar-se ao cluster Kubernetes. Certifique-se de que o Kind está em execução e o kubeconfig está corretamente configurado."
    echo_info "Para verificar a existência do cluster, execute 'kind get clusters'."
    exit 1
  fi
  echo_success "Conexão com o cluster Kubernetes estabelecida."
}

create_kind_cluster() {
  echo_info "Gerando arquivo de configuração do Kind..."

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
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o arquivo de configuração do Kind."; exit 1; fi

  # Verifica se o cluster já existe
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    echo_warn "O cluster Kind '$CLUSTER_NAME' já existe."
    echo_warn "Deseja reinstalá-lo (excluir e criar novamente) ou continuar com o cluster existente?"
    echo_warn "  [r] Reinstalar (excluir e criar novamente)"
    echo_warn "  [c] Continuar com o cluster existente"
    echo_warn "  [x] Sair"
    
    local choice
    while true; do
      printf "${COLOR_PROMPT}Escolha uma opção (r/c/x): ${COLOR_RESET}" # Corrigido para usar printf
      read -r choice
      case "$choice" in
        [rR])
          echo_info "Reinstalando o cluster '$CLUSTER_NAME'..."
          remove_kind_cluster # Chama a função para remover o cluster
          break
          ;;
        [cC])
          echo_info "Continuando com o cluster existente '$CLUSTER_NAME'."
          echo_success "Cluster Kind pronto para uso."
          return # Sai da função, não tenta criar o cluster
          ;;
        [xX])
          echo_info "Operação cancelada. Saindo."
          exit 0
          ;;
        *)
          echo_error "Opção inválida. Por favor, escolha 'r' para reinstalar, 'c' para continuar ou 'x' para sair."
          ;;
      esac
    done
  fi

  echo_info "Criando cluster Kind ($CLUSTER_NAME)... Este processo pode levar vários minutos."
  kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG_FILE"
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o cluster Kind."; exit 1; fi

  echo_info "🔧 Desabilitando restart automático dos containers do Kind..."
  for container in $(docker ps -a --filter name="$CLUSTER_NAME" --format "{{.Names}}"); do
    docker update --restart=no "$container"
  done

  echo_success "✅ Cluster Kind criado e configurado com restart=‘no’."
}

start_kind_cluster() {
  echo_info "Iniciando cluster Kind ($CLUSTER_NAME)..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    # Clusters Kind são compostos por contêineres Docker. O comando 'docker start' é usado para iniciá-los.
    local containers=$(docker ps -a --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --format "{{.Names}}")
    if [[ -n "$containers" ]]; then
      echo_info "Iniciando contêineres Docker do cluster Kind: $containers"
      docker start $containers
      if [ $? -ne 0 ]; then echo_error "Falha ao iniciar contêineres do cluster Kind."; exit 1; fi
      echo_success "Cluster Kind '$CLUSTER_NAME' iniciado."
      # Aguarda a conectividade do kubectl para garantir que o cluster esteja operacional.
      echo_info "Aguardando o cluster Kind estar pronto para aceitar conexões kubectl..."
      local start_time=$(date +%s)
      local timeout=120 # Timeout de 2 minutos
      while ! kubectl cluster-info &>/dev/null; do
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))
        if [[ $elapsed_time -ge $timeout ]]; then
          echo_error "Tempo limite excedido ao aguardar o cluster Kind estar pronto."
          exit 1
        fi
        echo_info "Aguardando conexão kubectl... ($elapsed_time/${timeout}s)"
        sleep 5
      done
      echo_success "Cluster Kind pronto para uso."
    else
      echo_warn "Nenhum contêiner Docker encontrado para o cluster Kind '$CLUSTER_NAME'. O cluster pode não existir ou já estar em execução."
    fi
  else
    echo_warn "Nenhum cluster Kind com o nome '$CLUSTER_NAME' encontrado. Por favor, crie o cluster primeiro."
  fi
}

stop_kind_cluster() {
  echo_info "Parando cluster Kind ($CLUSTER_NAME)..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    # Clusters Kind são compostos por contêineres Docker. O comando 'docker stop' é usado para pará-los.
    local containers=$(docker ps --filter "label=io.x-k8s.kind.cluster=${CLUSTER_NAME}" --format "{{.Names}}")
    if [[ -n "$containers" ]]; then
      echo_info "Parando contêineres Docker do cluster Kind: $containers"
      docker stop $containers
      if [ $? -ne 0 ]; then echo_error "Falha ao parar contêineres do cluster Kind."; exit 1; fi
      echo_success "Cluster Kind '$CLUSTER_NAME' parado."
    else
      echo_warn "Nenhum contêiner Docker em execução encontrado para o cluster Kind '$CLUSTER_NAME'. O cluster pode já estar parado ou não existe."
    fi
  else
    echo_warn "Nenhum cluster Kind com o nome '$CLUSTER_NAME' encontrado."
  fi
}

install_nginx_ingress() {
  check_cluster_connection
  echo_info "Iniciando instalação do NGINX Ingress Controller via Helm..."

  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
  if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Helm 'ingress-nginx'."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Falha ao atualizar os repositórios Helm."; exit 1; fi

  helm upgrade --install nginx-ingress ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.ingressClassResource.name=nginx \
  --set controller.ingressClassResource.default=true \
  --set controller.service.type=NodePort \
  --set controller.service.nodePorts.http=30080 \
  --set controller.service.nodePorts.https=30443 \
  --set controller.minReadySeconds=5 \
  --set controller.progressDeadlineSeconds=60 \
  --wait --timeout 10m # Aguarda a conclusão da instalação com um tempo limite.

  if [ $? -ne 0 ]; then echo_error "Falha na instalação do NGINX Ingress Controller."; exit 1; fi
  echo_success "NGINX Ingress Controller instalado."
}

install_cert_manager() {
  check_cluster_connection
  echo_info "Iniciando instalação do cert-manager via Helm..."

  helm repo add jetstack https://charts.jetstack.io
  if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Helm 'jetstack'."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Falha ao atualizar os repositórios Helm."; exit 1; fi

  helm upgrade --install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace \
    --set installCRDs=true \
    --version "${CERT_MANAGER_CHART_VERSION}" \
    --wait --timeout 10m # Aguarda a conclusão da instalação com um tempo limite.

  if [ $? -ne 0 ]; then echo_error "Falha na instalação do cert-manager."; exit 1; fi
  echo_success "cert-manager instalado."
}

create_rancher_cert() {
  check_cluster_connection
  echo_info "Criando certificado autoassinado para o Rancher..."

  mkdir -p "$CERT_DIR"
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o diretório de certificados."; exit 1; fi

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
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o arquivo openssl.cnf."; exit 1; fi

  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" -config "$CERT_DIR/openssl.cnf"
  if [ $? -ne 0 ]; then echo_error "Falha ao gerar o certificado TLS."; exit 1; fi

  # Define permissões restritivas para a chave privada.
  chmod 600 "$CERT_DIR/tls.key"
  if [ $? -ne 0 ]; then echo_error "Falha ao definir permissões para tls.key."; exit 1; fi
  chmod 644 "$CERT_DIR/tls.crt"
  if [ $? -ne 0 ]; then echo_error "Falha ao definir permissões para tls.crt."; exit 1; fi
  
  kubectl create namespace cattle-system --dry-run=client -o yaml | kubectl apply -f -
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o namespace 'cattle-system'."; exit 1; fi

  kubectl -n cattle-system delete secret tls-ca --ignore-not-found
  # A verificação de erro não é necessária, pois '--ignore-not-found' lida com a ausência do secret.

  kubectl -n cattle-system create secret generic tls-ca \
    --from-file=cacerts.pem="$CERT_DIR/tls.crt"
  if [ $? -ne 0 ]; then echo_error "Falha ao criar o secret 'tls-ca'."; exit 1; fi

  echo_success "Certificado TLS para Rancher criado e aplicado."
}

install_rancher_server() {
  check_cluster_connection
  echo_info "Iniciando instalação do Rancher Server via Helm... Este processo pode levar vários minutos."

  # Solicita a senha de bootstrap do Rancher ao usuário, com validação de comprimento.
  RANCHER_PASSWORD="" # Garante que a variável esteja vazia no início do loop.
  while [[ ${#RANCHER_PASSWORD} -lt 12 ]]; do
    if [[ -n "$RANCHER_PASSWORD" ]]; then # Exibe o erro apenas se a senha foi digitada e é inválida
      echo_error "A senha deve conter no mínimo 12 caracteres."
    fi
    echo_info "Por favor, defina uma senha para o usuário 'admin' do Rancher."
    read -s -p "Digite a senha do Rancher (mínimo 12 caracteres): " RANCHER_PASSWORD
    echo # Adiciona uma nova linha após a entrada da senha.
  done

  helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
  if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Helm 'rancher-latest'."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Falha ao atualizar os repositórios Helm."; exit 1; fi

  helm upgrade --install rancher rancher-latest/rancher \
    --namespace cattle-system \
    --set hostname="$RANCHER_HOSTNAME" \
    --set bootstrapPassword="$RANCHER_PASSWORD" \
    --set ingress.ingressClassName=nginx \
    --set ingress.tls.source=secret \
    --set ingress.tls.secretName=tls-ca \
    --set privateCA=true \
    --set replicas=1 \
    --wait --timeout 600s # Aguarda a conclusão da instalação com um tempo limite.

  if [ $? -ne 0 ]; then echo_error "Falha na instalação do Rancher Server."; exit 1; fi
  echo_success "Rancher Server instalado."
}

install_monitoring() {
  check_cluster_connection
  echo_info "Iniciando instalação do Monitoring (Prometheus + Grafana) no cluster... Este processo pode levar vários minutos."

  # Adiciona o repositório de charts do Rancher.
  helm repo add rancher-charts https://charts.rancher.io || true # Permite que o comando não falhe se o repositório já existir.
  if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Helm 'rancher-charts'."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Falha ao atualizar os repositórios Helm."; exit 1; fi

  # Instala os Custom Resource Definitions (CRDs) obrigatórios.
  helm upgrade --install rancher-monitoring-crd rancher-charts/rancher-monitoring-crd \
  -n cattle-monitoring-system --create-namespace \
  --version "${RANCHER_MONITORING_CHART_VERSION}" --wait --timeout 5m
  if [ $? -ne 0 ]; then echo_error "Falha na instalação dos CRDs do Rancher Monitoring."; exit 1; fi

  # Instala o módulo de monitoramento com versão fixada.
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
  if [ $? -ne 0 ]; then echo_error "Falha na instalação do Rancher Monitoring."; exit 1; fi

  echo_success "Módulo de Monitoring instalado com sucesso no namespace cattle-monitoring-system."
}

install_metrics_server() {
  check_cluster_connection
  echo_info "Iniciando instalação do Metrics Server no cluster..."

  # Adiciona o repositório metrics-server, ignorando erros se já existir.
  helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/ || true
  if [ $? -ne 0 ]; then echo_error "Falha ao adicionar o repositório Helm 'metrics-server'."; exit 1; fi
  helm repo update
  if [ $? -ne 0 ]; then echo_error "Falha ao atualizar os repositórios Helm."; exit 1; fi

  # Verifica a existência do namespace kube-system.
  if ! kubectl get namespace kube-system &>/dev/null; then
    echo_info "Namespace kube-system não encontrado. Criando..."
    kubectl create namespace kube-system
    if [ $? -ne 0 ]; then echo_error "Falha ao criar o namespace 'kube-system'."; exit 1; fi
  fi

  # Instala ou atualiza o metrics-server via Helm.
  helm upgrade --install metrics-server metrics-server/metrics-server \
    -n kube-system \
    --wait --timeout 5m \
    --set args[0]=--kubelet-insecure-tls \
    --set args[1]=--kubelet-preferred-address-types=InternalIP

  if [ $? -eq 0 ]; then
    echo_success "Metrics Server instalado com sucesso no namespace kube-system."
  else
    echo_error "Falha na instalação do Metrics Server."
    exit 1
  fi
}


configure_hosts() {
  echo_info "Configurando o arquivo /etc/hosts..."
  if ! grep -q "$RANCHER_HOSTNAME" /etc/hosts; then
    echo "127.0.0.1 $RANCHER_HOSTNAME" | sudo tee -a /etc/hosts
    if [ $? -ne 0 ]; then echo_error "Falha ao ajustar o arquivo /etc/hosts."; exit 1; fi
    echo_success "O arquivo /etc/hosts foi ajustado para acessar $RANCHER_HOSTNAME"
  else
    echo_success "O arquivo /etc/hosts já contém a entrada para $RANCHER_HOSTNAME."
  fi
}

# ==================== FUNÇÕES DE LIMPEZA ====================

remove_kind_cluster() {
  echo_info "Iniciando remoção do cluster Kind..."
  if kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    read -p "Confirma a remoção do cluster Kind '$CLUSTER_NAME'? (s/N): " confirm
    if [[ "$confirm" == [sS] ]]; then
      kind delete cluster --name "$CLUSTER_NAME"
      if [ $? -ne 0 ]; then echo_error "Falha ao remover o cluster Kind."; exit 1; fi
      echo_success "Cluster Kind '$CLUSTER_NAME' removido com sucesso."
    else
      echo_info "Operação de remoção do cluster Kind cancelada."
    fi
  else
    echo_warn "Nenhum cluster Kind com o nome '$CLUSTER_NAME' encontrado."
  fi
}

cleanup_local_files() {
  echo_info "Removendo arquivos de configuração e certificados locais..."
  if [ -f "$KIND_CONFIG_FILE" ]; then
    rm "$KIND_CONFIG_FILE"
    echo_info "Arquivo de configuração Kind removido: $KIND_CONFIG_FILE"
  fi
  if [ -d "$CERT_DIR" ]; then
    rm -rf "$CERT_DIR"
    echo_info "Diretório de certificados removido: $CERT_DIR"
  fi
  echo_success "Limpeza de arquivos locais concluída."
}

# ==================== EXECUÇÃO PRINCIPAL ====================
show_menu() {
  echo ""
  echo -e "${COLOR_MENU_TITLE}Selecione a etapa a ser executada:${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}1) Instalar Docker${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}2) Configurar Docker (Systemd)${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}3) Configurar Sysctl${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}4) Instalar kubectl${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}5) Instalar Helm${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}6) Instalar Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}7) Instalar Rancher CLI${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}8) Criar Cluster Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}9) Instalar NGINX Ingress${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}10) Instalar cert-manager${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}11) Gerar certificado Rancher${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}12) Instalar Rancher Server${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}13) Configurar /etc/hosts${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}14) Instalar Monitoramento${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}15) Instalar Métricas do Servidor${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}16) Executar TODAS as etapas de instalação${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}17) Remover Cluster Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}18) Limpar arquivos locais (configuração, certificados)${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}19) Iniciar Cluster Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}20) Parar Cluster Kind${COLOR_RESET}"
  echo -e "${COLOR_MENU_OPTION}0) Sair${COLOR_RESET}"
  printf "${COLOR_PROMPT}Escolha uma opção: ${COLOR_RESET}" # Usando printf para garantir a coloração do prompt
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
        echo_info "Executando TODAS as etapas de instalação do ambiente..."
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
        echo_success "Todas as etapas de instalação foram concluídas com êxito!"
        echo_success "O Rancher está acessível em: https://$RANCHER_HOSTNAME"
        echo_warn "Se o usuário foi adicionado ao grupo 'docker', é necessário fazer logout/login ou reiniciar o terminal para aplicar as permissões."
        ;;
      17) remove_kind_cluster ;;
      18) cleanup_local_files ;;
      19) start_kind_cluster ;;
      20) stop_kind_cluster ;;
      0) 
        echo_success "Encerrando script. Operação concluída."
        exit 0
        ;;
      *) 
        echo_warn "Opção inválida. Por favor, tente novamente."
        ;;
    esac
    echo "" # Adiciona uma linha em branco para melhorar a legibilidade do menu.
  done
}

main