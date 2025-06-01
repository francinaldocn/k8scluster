# Local Kubernetes Environment with Kind and Rancher

This project provides a Bash script to quickly set up a development and learning environment with Kubernetes (Kind) and Rancher on your local machine. It automates the installation of prerequisites, cluster creation, and deployment of essential components like NGINX Ingress, cert-manager, Rancher Server, and monitoring tools.

## Features

- **Full Automation**: Installs Docker, kubectl, Helm, Kind, and Rancher CLI.

- **Configurable Kind Cluster**: Creates a multi-node Kind cluster optimized for Rancher, with port mapping and sysctl adjustments.

- **Deployment of Essential Components**:
  - **NGINX Ingress Controller**: Manages external access to the cluster.
  - **cert-manager**: Automates TLS certificate issuance and renewal.
  - **Rancher Server**: Kubernetes management platform.
  - **Rancher Monitoring**: Deploys Prometheus and Grafana for cluster monitoring.
  - **Metrics Server**: Enables resource metrics for `kubectl top`.

- **Enhanced Interactivity**: Interactive menu with options to execute steps individually or all at once, with colorized log messages for better visual feedback.

- **Error Handling**: Includes prerequisite checks, error handling for critical commands, and user input validation.

- **Cluster Management**: Functions to start, stop, and delete the Kind cluster.

- **Compatibility**: Designed for Debian/Ubuntu-based and Red Hat-based Linux distributions.

## Prerequisites

- A Linux machine (tested on Debian/Ubuntu and RHEL-based distros).
- Sudo access to install packages and configure the system.
- Internet connection to download tools and container images.

## How to Use

1. Clone the Repository

```bash
git clone https://github.com/francinaldocn/k8scluster.git
cd k8scluster/en
````

2. Make the Script Executable

```bash
chmod +x setup-k8s-kind-rancher-en.sh
```

3. Run the Script

Execute the script and follow the interactive menu instructions:

```bash
./setup-k8s-kind-rancher-en.sh
```

The script will display a menu with the following options:

```bash
Select the step to execute:
1) Install Docker
2) Configure Docker (Systemd)
3) Configure Sysctl
4) Install kubectl
5) Install Helm
6) Install Kind
7) Install Rancher CLI
8) Create Kind Cluster
9) Install NGINX Ingress
10) Install cert-manager
11) Generate Rancher Certificate
12) Install Rancher Server
13) Configure /etc/hosts
14) Install Monitoring
15) Install Metrics Server
16) Run ALL installation steps
17) Delete Kind Cluster
18) Clean local files (config, certificates)
19) Start Kind Cluster
20) Stop Kind Cluster
0) Exit
Choose an option:
```

## Recommended Options

* **For a full first-time installation**, select **16) Run ALL installation steps.** The script will handle all prerequisites and components.

* **To manage the Kind cluster after installation**, use:

  * **19) Start Kind Cluster**
  * **20) Stop Kind Cluster**

> Note: The Kind cluster is not configured to start automatically with the system.

## Post-installation

After successfully completing all steps (option 16):

1. **Restart your terminal or log out and log back in** if your user was added to the `docker` group during installation. This ensures the new permissions take effect.

2. Access Rancher: Open your browser and navigate to `https://rancher.localhost`.

   * Since a self-signed certificate is used, your browser will likely show a security warning. Proceed by accepting the risk to access the Rancher UI.
   * The initial password for the `admin` user is the one you set during the script execution.

3. **Explore your Cluster**: Use `kubectl get pods -A` to check the status of pods in your cluster.

## Common Troubleshooting

* **"Permission denied"** or repeated **`sudo` prompts**: Make sure your user has been added to the `docker` group and that you've restarted your terminal or logged out and back in.

* **Kind cluster won't start / Pods in Pending or CrashLoopBackOff**:

  * Check if your host machine has **enough resources** (CPU and RAM) to run the Kind cluster and installed services. Multi-node clusters with addons like Rancher require significant resources.
  * Inspect logs of problematic pods:

  ```bash
  kubectl describe pod <pod-name> -n <namespace>
  kubectl logs <pod-name> -n <namespace>
  ```

  * **Try restarting the Docker service** (`sudo systemctl restart docker`) and then start the Kind cluster via the script.

  * Consider **deleting and recreating the Kind cluster** (options 17 and 8 in the script) to start fresh.

* **Rancher access issues**: Check the `/etc/hosts` entry to ensure it includes the correct mapping.

## Contributing

Feel free to open issues or pull requests in this repository if you encounter bugs, have suggestions for improvements, or want to add new features.

## License

This project is open-source and licensed under the [MIT License](https://opensource.org/licenses/MIT).