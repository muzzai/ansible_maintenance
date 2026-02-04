# Copilot Instructions for ansible_maintenance

## Project Overview
This repository automates maintenance tasks for AWX-managed infrastructure using Ansible. It is organized around playbooks and roles, with a focus on AWS EC2 management and secret handling via HashiCorp Vault.

## Architecture & Key Components
- **Playbooks** (`playbooks/`):
  - `configure_monitoring_host.yml`: Gathers AWS EC2 info, parses instance names, checks port 445, and builds a list of instances.
  - `restart_monitoring_host.yml`: Stops and starts EC2 instances in the `monitoring_hosts` group, with retries and state checks.
- **Roles** (`roles/`):
  - `build_connection_details`: Retrieves secrets for hosts, creates temporary private key files, and sets connection details for SSH.
  - `manage_secret`: Handles reading/writing secrets to HashiCorp Vault using the `community.hashi_vault` collection. Validates parameters and manages CA certificates from environment variables.
- **Templates** (`templates/`): Jinja2 templates for config files (e.g., `config.yml.j2`, `fluent-bit.yml.j2`).
- **Group Variables** (`group_vars/`): Used for inventory and host-specific configuration.

## Developer Workflows
- **Dependencies**: Install Ansible Galaxy collections as specified in `requirements.yml`:
  ```sh
  ansible-galaxy install -r requirements.yml
  ```
- **Running Playbooks**: Use standard Ansible commands, e.g.:
  ```sh
  ansible-playbook playbooks/configure_monitoring_host.yml -e aws_region=<region>
  ansible-playbook playbooks/restart_monitoring_host.yml -i <inventory>
  ```
- **Vault Integration**: Ensure environment variables (`VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`, `VAULT_CA_CERT_PEM`) are set for secret management.

## Project-Specific Patterns & Conventions
**Module Naming**: Always use fully qualified collection names (FQCN) for all Ansible module references (e.g., `amazon.aws.ec2_instance`, `ansible.builtin.assert`).
- **Vault**: Uses `community.hashi_vault` for secret storage/retrieval.
- **Prometheus**: (Optional) `prometheus.prometheus` collection is listed in requirements.

## Examples
- To retrieve a host's SSH key:
  - The `build_connection_details` role calls `manage_secret` with `action: get` and writes the key to a temp file for SSH.
- To store a secret:
  - Use `manage_secret` with `action: write` and provide a non-empty payload.

## Key Files & Directories
- `playbooks/` — Main automation entry points
- `roles/manage_secret/` — Vault integration logic
- `roles/build_connection_details/` — Host connection setup
- `requirements.yml` — Dependency management

---
**Feedback:** Please review for missing or unclear sections. Suggest improvements or point out project-specific patterns not covered here.
