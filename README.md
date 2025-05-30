## Ambiente Kubernetes Local com Kind e Rancher
Este projeto oferece um script Bash para configurar rapidamente um ambiente de desenvolvimento e estudo com Kubernetes (Kind) e Rancher em sua máquina local. Ele automatiza a instalação de pré-requisitos, a criação do cluster e a implantação de componentes essenciais como NGINX Ingress, cert-manager e o próprio Rancher Server, além de ferramentas de monitoramento.

### Recursos
- **Automação Completa**: Instala Docker, kubectl, Helm e Kind, além de Rancher CLI.

- **Cluster Kind Configurável**: Cria um cluster Kind de múltiplos nós otimizado para o Rancher, com mapeamento de portas e ajuste de sysctls.

- **Implantação de Componentes Essenciais**:
    - **NGINX Ingress Controller**: Gerencia o acesso externo ao cluster.
    - **cert-manager**: Automatiza a emissão e renovação de certificados TLS.
    - **Rancher Server**: Plataforma de gerenciamento de Kubernetes.
    - **Rancher Monitoring**: Implanta Prometheus e Grafana para monitoramento do cluster.
    - **Metrics Server**: Habilita métricas de recursos para kubectl top.

- **Interatividade Aprimorada**: Menu interativo com opções para executar etapas individualmente ou em conjunto, e mensagens de log coloridas para melhor feedback visual.

- **Tratamento de Erros**: Inclui verificações de pré-requisitos, tratamento de erros para comandos críticos e validação de entrada do usuário.

- **Gerenciamento do Cluster**: Funções para iniciar, parar e remover o cluster Kind.

- **Compatibilidade**: Desenvolvido para distribuições Linux baseadas em Debian/Ubuntu e Red Hat.

### Pré-requisitos

- Uma máquina Linux (testado em Debian/Ubuntu e RHEL-based).
- Acesso sudo para instalar pacotes e configurar o sistema.
- Conexão com a internet para download de ferramentas e imagens.

### Como Usar
1. Clonar o Repositório
```Bash
git clone https://github.com/francinaldocn/k8scluster.git
cd k8scluster
```
2. Tornar o Script Executável
```Bash
chmod +x setup-k8s-kind-rancher.sh
```
3. Executar o Script
Execute o script e siga as instruções do menu interativo:

```Bash
./setup-k8s-kind-rancher.sh
```

O script apresentará um menu com as seguintes opções:
```Bash
Selecione a etapa a ser executada:
1) Instalar Docker
2) Configurar Docker (Systemd)
3) Configurar Sysctl
4) Instalar kubectl
5) Instalar Helm
6) Instalar Kind
7) Instalar Rancher CLI
8) Criar Cluster Kind
9) Instalar NGINX Ingress
10) Instalar cert-manager
11) Gerar certificado Rancher
12) Instalar Rancher Server
13) Configurar /etc/hosts
14) Instalar Monitoramento
15) Instalar Métricas do Servidor
16) Executar TODAS as etapas de instalação
17) Remover Cluster Kind
18) Limpar arquivos locais (configuração, certificados)
19) Iniciar Cluster Kind
20) Parar Cluster Kind
0) Sair
Escolha uma opção:
```

### Opções Recomendadas:

- **Para uma instalação completa pela primeira vez**: Escolha a opção **16) Executar TODAS as etapas de instalação.** O script cuidará de todos os pré-requisitos e componentes.

- **Para gerenciar o cluster Kind após a instalação**: Use as opções **19) Iniciar Cluster Kind** e **20) Parar Cluster Kind.** O cluster Kind não é configurado para iniciar automaticamente com o sistema.

### Pós-instalação

Após a conclusão bem-sucedida de todas as etapas (opção 16):

1. **Reinicie seu terminal ou faça logout/login** se o seu usuário foi adicionado ao grupo `docker` durante a instalação. Isso garante que as novas permissões sejam aplicadas.

2. Acesse o Rancher: Abra seu navegador e navegue para `https://rancher.localhost`.
    - Como um certificado autoassinado é usado, seu navegador provavelmente exibirá um aviso de segurança. Prossiga aceitando o risco para acessar a interface do Rancher.
    - A senha inicial do usuário `admin` será a que você definiu durante a execução do script.
    
3. **Explore seu Cluster**: Use `kubectl get pods -A` para verificar o status dos pods em seu cluster.

### Resolução de Problemas Comuns

- **"Permissão negada"** ou `sudo` **repetitivo**: Certifique-se de que seu usuário foi adicionado ao grupo `docker` e que você reiniciou o terminal ou fez logout/login.

- **Cluster Kind não inicia/pods em Pending ou CrashLoopBackOff**:
    - Verifique se sua máquina host possui **recursos suficientes** (CPU e RAM) para o cluster Kind e os serviços instalados. Clusters com múltiplos nós e add-ons como Rancher exigem recursos significativos.
    - Inspecione os logs de pods problemáticos:
    ```Bash
    kubectl describe pod <nome-do-pod> -n <namespace>
    kubectl logs <nome-do-pod> -n <namespace>
    ```
    - **Tente reiniciar o serviço Docker** (`sudo systemctl restart docker`) e depois inicie o cluster Kind via script.

    - Considere **remover e recriar o cluster Kind** (opções 17 e 8 do script) para iniciar com um ambiente limpo.

- **Problemas de acesso ao Rancher**: Verifique a entrada no seu arquivo `/etc/hosts`.

### Contribuição

Sinta-se à vontade para abrir issues ou pull requests neste repositório caso encontre bugs, tenha sugestões de melhoria ou queira adicionar novas funcionalidades.

### Licença
Este projeto é de código aberto e está sob a licença [MIT License](https://opensource.org/licenses/MIT).