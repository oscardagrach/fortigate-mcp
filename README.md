# fortigate-mcp

An MCP (Model Context Protocol) server for managing FortiGate firewalls via the FortiOS REST API. Provides 361 tools covering system management, firewall policies, routing, VPN, security profiles, user authentication, DNS, monitoring, and more.

## Requirements

- Node.js 18+
- A FortiGate firewall with REST API access enabled
- An API token generated on the FortiGate

## Generating a FortiGate API Token

1. Log in to the FortiGate web UI
2. Go to **System > Administrators**
3. Create a new REST API Admin or edit an existing one
4. Under **Administrator Profile**, assign an appropriate profile (e.g., `super_admin` for full access, or a custom read-only profile)
5. Optionally restrict **Trusted Hosts** to limit API access by source IP
6. Save and copy the generated API token

## Installation

```bash
npm install
npm run build
```

## Configuration

The server is configured via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `FORTIGATE_HOST` | Yes | - | FortiGate hostname or IP address |
| `FORTIGATE_API_TOKEN` | Yes | - | REST API token |
| `FORTIGATE_PORT` | No | `443` | HTTPS port |
| `FORTIGATE_VERIFY_SSL` | No | `true` | Set to `false` to skip TLS verification (common for self-signed certs) |

## Usage

### With Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "node",
      "args": ["/path/to/fortigate-mcp/dist/index.js"],
      "env": {
        "FORTIGATE_HOST": "192.168.1.1",
        "FORTIGATE_API_TOKEN": "your-api-token-here",
        "FORTIGATE_VERIFY_SSL": "false"
      }
    }
  }
}
```

### With Claude Code

Add to your Claude Code MCP settings:

```bash
claude mcp add fortigate -- node /path/to/fortigate-mcp/dist/index.js
```

Then set the required environment variables before launching, or configure them in your MCP settings.

### Standalone

```bash
FORTIGATE_HOST=192.168.1.1 \
FORTIGATE_API_TOKEN=your-token \
FORTIGATE_VERIFY_SSL=false \
npm start
```

### Development

```bash
FORTIGATE_HOST=192.168.1.1 \
FORTIGATE_API_TOKEN=your-token \
FORTIGATE_VERIFY_SSL=false \
npm run dev
```

## Available Tools (361)

### System

| Tool | Description |
|---|---|
| `get_system_status` | Get system status (hostname, firmware, serial number) |
| `get_system_resources` | Get CPU, memory, and disk usage statistics |
| `get_system_performance` | Get system performance metrics |
| `get_global_settings` | Get system global settings (admin port, timezone, language) |
| `update_global_settings` | Update system global settings (hostname, timezone, admin ports) |
| `get_vdoms` | List all virtual domains (VDOMs) |
| `get_admins` | List system administrator accounts |
| `get_admin_profiles` | List admin access profiles (permissions) |
| `get_firmware_versions` | Check available firmware versions |
| `get_certificates` | List installed local certificates |
| `get_license_status` | Get FortiGuard license and subscription status |
| `get_config_backup` | Download the full configuration backup |

### Interfaces

| Tool | Description |
|---|---|
| `get_interfaces` | List all network interfaces with config and status |
| `get_interface` | Get details for a specific interface |
| `update_interface` | Update interface configuration (IP, allowaccess, alias, etc.) |
| `get_interface_stats` | Get real-time interface traffic statistics and link status |
| `get_zones` | List all system zones and their interface members |

### Firewall Policies

| Tool | Description |
|---|---|
| `get_firewall_policies` | List all firewall policies |
| `get_firewall_policy` | Get a specific policy by ID |
| `create_firewall_policy` | Create a new firewall policy |
| `update_firewall_policy` | Update an existing policy by ID |
| `delete_firewall_policy` | Delete a policy by ID |

### IPv6 Firewall Policies

| Tool | Description |
|---|---|
| `get_firewall_policies6` | List all IPv6 firewall policies |
| `get_firewall_policy6` | Get a specific IPv6 policy by ID |
| `create_firewall_policy6` | Create a new IPv6 firewall policy |
| `update_firewall_policy6` | Update an existing IPv6 policy by ID |
| `delete_firewall_policy6` | Delete an IPv6 policy by ID |

### Central SNAT

| Tool | Description |
|---|---|
| `get_central_snat_map` | List all central SNAT map entries |
| `get_central_snat_entry` | Get a specific central SNAT entry by ID |
| `create_central_snat_entry` | Create a new central SNAT map entry |
| `update_central_snat_entry` | Update an existing central SNAT entry by ID |
| `delete_central_snat_entry` | Delete a central SNAT entry by ID |

### DoS Policies

| Tool | Description |
|---|---|
| `get_dos_policies` | List all DoS protection policies |
| `get_dos_policy` | Get a specific DoS policy by ID |
| `create_dos_policy` | Create a new DoS protection policy |
| `update_dos_policy` | Update an existing DoS policy by ID |
| `delete_dos_policy` | Delete a DoS policy by ID |

### Multicast Policies

| Tool | Description |
|---|---|
| `get_multicast_policies` | List all multicast firewall policies |
| `get_multicast_policy` | Get a specific multicast policy by ID |
| `create_multicast_policy` | Create a new multicast firewall policy |
| `update_multicast_policy` | Update an existing multicast policy by ID |
| `delete_multicast_policy` | Delete a multicast policy by ID |

### Proxy Policies

| Tool | Description |
|---|---|
| `get_proxy_policies` | List all explicit/transparent proxy policies |
| `get_proxy_policy` | Get a specific proxy policy by ID |
| `create_proxy_policy` | Create a new proxy policy |
| `update_proxy_policy` | Update an existing proxy policy by ID |
| `delete_proxy_policy` | Delete a proxy policy by ID |

### Local-in Policies

| Tool | Description |
|---|---|
| `get_local_in_policies` | List all local-in policies (traffic to the FortiGate itself) |
| `get_local_in_policy` | Get a specific local-in policy by ID |
| `create_local_in_policy` | Create a new local-in policy |
| `update_local_in_policy` | Update an existing local-in policy by ID |
| `delete_local_in_policy` | Delete a local-in policy by ID |

### Address Objects

| Tool | Description |
|---|---|
| `get_addresses` | List all firewall address objects |
| `get_address` | Get a specific address object by name |
| `create_address` | Create a new address object (ipmask, iprange, or fqdn) |
| `update_address` | Update an existing address object by name |
| `delete_address` | Delete an address object by name |
| `get_address_groups` | List all firewall address groups |

### IPv6 Address Objects

| Tool | Description |
|---|---|
| `get_addresses6` | List all IPv6 firewall address objects |
| `get_address6` | Get a specific IPv6 address object by name |
| `create_address6` | Create a new IPv6 address object |
| `update_address6` | Update an existing IPv6 address object by name |
| `delete_address6` | Delete an IPv6 address object by name |
| `get_address_groups6` | List all IPv6 firewall address groups |

### Multicast Addresses

| Tool | Description |
|---|---|
| `get_multicast_addresses` | List all firewall multicast address objects |

### Services

| Tool | Description |
|---|---|
| `get_services` | List all custom firewall service objects |
| `get_service_groups` | List all firewall service groups |
| `get_service_categories` | List all firewall service categories |
| `get_internet_services` | List all predefined internet service objects |

### Firewall Schedules

| Tool | Description |
|---|---|
| `get_schedules_recurring` | List all recurring firewall schedules |
| `get_schedules_onetime` | List all one-time firewall schedules |

### Virtual IPs (DNAT / Port Forwarding)

| Tool | Description |
|---|---|
| `get_vips` | List all VIP objects |
| `get_vip` | Get a specific VIP by name |
| `create_vip` | Create a VIP for DNAT / port forwarding |
| `delete_vip` | Delete a VIP by name |
| `get_vip_groups` | List all firewall virtual IP groups |

### IP Pools (SNAT)

| Tool | Description |
|---|---|
| `get_ip_pools` | List all IP pools used for source NAT |
| `get_ip_pools6` | List all IPv6 IP pools for source NAT |

### Shaping Policies

| Tool | Description |
|---|---|
| `get_shaping_profiles` | List all firewall traffic shaping profiles |
| `get_shaping_policies` | List all firewall traffic shaping policies |
| `get_shaping_policy` | Get a specific shaping policy by ID |
| `create_shaping_policy` | Create a new traffic shaping policy |
| `update_shaping_policy` | Update an existing shaping policy by ID |
| `delete_shaping_policy` | Delete a shaping policy by ID |

### Routing

| Tool | Description |
|---|---|
| `get_routing_table` | Get the active routing table (IPv4) |
| `get_static_routes` | List all configured static routes |
| `create_static_route` | Create a new static route |
| `update_static_route` | Update an existing static route by ID |
| `delete_static_route` | Delete a static route by ID |

### BGP

| Tool | Description |
|---|---|
| `get_bgp_config` | Get BGP configuration (neighbors, networks) |
| `get_bgp_paths` | Get BGP learned/advertised route paths |
| `get_bgp_neighbors_status` | Get BGP neighbor status (state, uptime, prefixes received) |
| `get_bgp_networks` | List BGP network entries being advertised |
| `get_bgp_redistribute` | Get BGP route redistribution settings |
| `update_bgp_config` | Update BGP config (router-id, AS, neighbors, networks) |

### OSPF

| Tool | Description |
|---|---|
| `get_ospf_config` | Get OSPF configuration (areas, interfaces) |
| `get_ospf_neighbors` | Get OSPF neighbor adjacency status |
| `update_ospf_config` | Update OSPF config (router-id, areas, redistribute) |

### Route Policy

| Tool | Description |
|---|---|
| `get_prefix_lists` | List all router prefix lists |
| `get_route_maps` | List all router route maps |
| `get_community_lists` | List all BGP community lists |
| `get_prefix_lists6` | List all IPv6 router prefix lists |

### Access Lists

| Tool | Description |
|---|---|
| `get_access_lists` | List all router access lists (IPv4) |
| `get_access_list` | Get a specific router access list by name |
| `create_access_list` | Create a new router access list |
| `update_access_list` | Update an existing router access list |
| `delete_access_list` | Delete a router access list by name |
| `get_access_lists6` | List all IPv6 router access lists |

### AS Path Lists

| Tool | Description |
|---|---|
| `get_aspath_lists` | List all BGP AS path lists |
| `get_aspath_list` | Get a specific AS path list by name |
| `create_aspath_list` | Create a new BGP AS path list |
| `update_aspath_list` | Update an existing AS path list |
| `delete_aspath_list` | Delete an AS path list by name |

### BFD

| Tool | Description |
|---|---|
| `get_bfd_config` | Get BFD (Bidirectional Forwarding Detection) configuration |
| `update_bfd_config` | Update BFD configuration |

### RIP

| Tool | Description |
|---|---|
| `get_rip_config` | Get RIP routing configuration |
| `update_rip_config` | Update RIP routing configuration |

### IS-IS

| Tool | Description |
|---|---|
| `get_isis_config` | Get IS-IS routing configuration |
| `update_isis_config` | Update IS-IS routing configuration |

### Multicast Routing

| Tool | Description |
|---|---|
| `get_multicast_routing_config` | Get multicast routing (PIM) configuration |
| `update_multicast_routing_config` | Update multicast routing (PIM) configuration |

### Router Policy (PBR)

| Tool | Description |
|---|---|
| `get_router_policies` | List all policy-based routing rules |
| `get_router_policy` | Get a specific PBR rule by sequence number |
| `create_router_policy` | Create a new policy-based routing rule |
| `update_router_policy` | Update an existing PBR rule |
| `delete_router_policy` | Delete a PBR rule by sequence number |

### Key Chains

| Tool | Description |
|---|---|
| `get_key_chains` | List all router authentication key chains |
| `get_key_chain` | Get a specific key chain by name |
| `create_key_chain` | Create a new key chain |
| `update_key_chain` | Update an existing key chain |
| `delete_key_chain` | Delete a key chain by name |

### IPv6 Static Routes

| Tool | Description |
|---|---|
| `get_static_routes6` | List all IPv6 static routes |
| `get_static_route6` | Get a specific IPv6 static route by ID |
| `create_static_route6` | Create a new IPv6 static route |
| `update_static_route6` | Update an existing IPv6 static route by ID |
| `delete_static_route6` | Delete an IPv6 static route by ID |

### Firewall Policy Statistics

| Tool | Description |
|---|---|
| `get_policy_stats` | Get policy hit counts, byte/packet stats, last-used timestamps |

### SD-WAN

| Tool | Description |
|---|---|
| `get_sdwan_config` | Get SD-WAN configuration (members, health checks, rules) |
| `get_sdwan_health_check` | Get SD-WAN health check status |
| `get_sdwan_members` | Get SD-WAN member interface status and statistics |
| `get_sdwan_sla_log` | Get SLA performance log for a health check (latency, jitter, loss over time) |
| `get_sdwan_zones` | List SD-WAN zone configurations and member interfaces |
| `update_sdwan_config` | Update SD-WAN settings (status, load-balance-mode, etc.) |

### VPN

| Tool | Description |
|---|---|
| `get_ipsec_vpn_status` | Get IPsec VPN tunnel status and statistics |
| `get_ipsec_phase1` | List IPsec Phase 1 interface configurations |
| `get_ipsec_phase2` | List IPsec Phase 2 interface configurations |
| `get_ssl_vpn_status` | Get SSL VPN sessions and connected users |
| `get_ssl_vpn_settings` | Get SSL VPN server settings |

### SSL VPN Portals

| Tool | Description |
|---|---|
| `get_ssl_vpn_portals` | List all SSL VPN web portal profiles |
| `get_ssl_vpn_portal` | Get a specific SSL VPN portal profile by name |
| `create_ssl_vpn_portal` | Create a new SSL VPN portal profile |
| `update_ssl_vpn_portal` | Update an existing SSL VPN portal profile |
| `delete_ssl_vpn_portal` | Delete an SSL VPN portal profile by name |

### SSL VPN Realms

| Tool | Description |
|---|---|
| `get_ssl_vpn_realms` | List all SSL VPN authentication realms |
| `get_ssl_vpn_realm` | Get a specific SSL VPN realm by name |
| `create_ssl_vpn_realm` | Create a new SSL VPN realm |
| `update_ssl_vpn_realm` | Update an existing SSL VPN realm |
| `delete_ssl_vpn_realm` | Delete an SSL VPN realm by name |

### PPTP

| Tool | Description |
|---|---|
| `get_pptp_settings` | Get PPTP VPN server settings |
| `update_pptp_settings` | Update PPTP VPN server settings |

### L2TP

| Tool | Description |
|---|---|
| `get_l2tp_settings` | Get L2TP VPN server settings |
| `update_l2tp_settings` | Update L2TP VPN server settings |

### VPN Certificates

| Tool | Description |
|---|---|
| `get_vpn_certificate_cas` | List all VPN CA certificates |
| `get_vpn_certificate_remote` | List all remote VPN certificates |
| `get_vpn_certificate_crl` | List all VPN certificate revocation lists |

### Security Profiles

| Tool | Description |
|---|---|
| `get_webfilter_profiles` | List all web filter profiles |
| `get_antivirus_profiles` | List all antivirus profiles |
| `get_ips_sensors` | List all IPS sensor profiles |
| `get_application_lists` | List all application control profiles |
| `get_dnsfilter_profiles` | List all DNS filter profiles |
| `get_ssl_ssh_profiles` | List all SSL/SSH inspection profiles |

### WAF (Web Application Firewall)

| Tool | Description |
|---|---|
| `get_waf_profiles` | List all WAF profiles |
| `get_waf_profile` | Get a specific WAF profile by name |

### DLP (Data Leak Prevention)

| Tool | Description |
|---|---|
| `get_dlp_sensors` | List all DLP sensor profiles |
| `get_dlp_sensor` | Get a specific DLP sensor by name |
| `get_dlp_fp_doc_sources` | List all DLP fingerprint document sources |

### Email Filter

| Tool | Description |
|---|---|
| `get_emailfilter_profiles` | List all email filter profiles |
| `get_emailfilter_profile` | Get a specific email filter profile by name |

### ICAP

| Tool | Description |
|---|---|
| `get_icap_servers` | List all ICAP server configurations |
| `get_icap_profiles` | List all ICAP profiles |
| `get_icap_profile` | Get a specific ICAP profile by name |

### VoIP

| Tool | Description |
|---|---|
| `get_voip_profiles` | List all VoIP/SIP security profiles |
| `get_voip_profile` | Get a specific VoIP profile by name |

### File Filter

| Tool | Description |
|---|---|
| `get_file_filter_profiles` | List all file filter profiles |
| `get_file_filter_profile` | Get a specific file filter profile by name |

### Video Filter

| Tool | Description |
|---|---|
| `get_video_filter_profiles` | List all video filter profiles |

### SCTP Filter

| Tool | Description |
|---|---|
| `get_sctp_filter_profiles` | List all SCTP filter profiles |

### Users

| Tool | Description |
|---|---|
| `get_local_users` | List local user accounts |
| `get_user_groups` | List user groups |
| `get_banned_users` | List currently banned user IPs |

### LDAP Servers

| Tool | Description |
|---|---|
| `get_ldap_servers` | List all configured LDAP server connections |
| `get_ldap_server` | Get a specific LDAP server configuration by name |
| `create_ldap_server` | Create a new LDAP server connection |
| `update_ldap_server` | Update an existing LDAP server configuration |
| `delete_ldap_server` | Delete an LDAP server configuration by name |

### RADIUS Servers

| Tool | Description |
|---|---|
| `get_radius_servers` | List all configured RADIUS server connections |
| `get_radius_server` | Get a specific RADIUS server configuration by name |
| `create_radius_server` | Create a new RADIUS server connection |
| `update_radius_server` | Update an existing RADIUS server configuration |
| `delete_radius_server` | Delete a RADIUS server configuration by name |

### TACACS+ Servers

| Tool | Description |
|---|---|
| `get_tacacs_servers` | List all configured TACACS+ server connections |
| `get_tacacs_server` | Get a specific TACACS+ server configuration by name |
| `create_tacacs_server` | Create a new TACACS+ server connection |
| `update_tacacs_server` | Update an existing TACACS+ server configuration |
| `delete_tacacs_server` | Delete a TACACS+ server configuration by name |

### SAML

| Tool | Description |
|---|---|
| `get_saml_servers` | List all configured SAML IdP server connections |
| `get_saml_server` | Get a specific SAML IdP server configuration by name |
| `create_saml_server` | Create a new SAML IdP server connection |
| `update_saml_server` | Update an existing SAML IdP server configuration |
| `delete_saml_server` | Delete a SAML IdP server configuration by name |

### FortiToken

| Tool | Description |
|---|---|
| `get_fortitokens` | List all FortiToken two-factor authentication tokens |

### FSSO (Fortinet SSO)

| Tool | Description |
|---|---|
| `get_fsso_servers` | List all FSSO agent/polling connections |
| `get_fsso_server` | Get a specific FSSO agent/polling connection by ID |
| `create_fsso_server` | Create a new FSSO agent/polling connection |
| `update_fsso_server` | Update an existing FSSO agent/polling connection |
| `delete_fsso_server` | Delete an FSSO agent/polling connection by ID |

### Web Proxy

| Tool | Description |
|---|---|
| `get_web_proxy_global` | Get global web proxy settings |
| `update_web_proxy_global` | Update global web proxy settings |
| `get_web_proxy_explicit` | Get explicit web proxy settings |
| `update_web_proxy_explicit` | Update explicit web proxy settings |
| `get_web_proxy_forward_servers` | List all web proxy forward servers |
| `get_web_proxy_forward_server` | Get a specific forward server by name |
| `create_web_proxy_forward_server` | Create a new forward server |
| `update_web_proxy_forward_server` | Update an existing forward server |
| `delete_web_proxy_forward_server` | Delete a forward server by name |
| `get_web_proxy_url_matches` | List all URL match rules |
| `create_web_proxy_url_match` | Create a new URL match rule |
| `delete_web_proxy_url_match` | Delete a URL match rule by name |

### DHCP

| Tool | Description |
|---|---|
| `get_dhcp_leases` | List all DHCP leases across interfaces |
| `get_dhcp_servers` | List all DHCP server configurations |

### DNS

| Tool | Description |
|---|---|
| `get_dns_settings` | Get DNS server configuration |
| `update_dns_settings` | Update DNS server settings (primary, secondary, domain) |
| `get_dns_database` | List all DNS database zones |
| `get_dns_database_zone` | Get a specific DNS zone by name (includes all entries) |
| `create_dns_database_zone` | Create a new DNS zone (master/slave/forwarder) with optional initial entries |
| `update_dns_database_zone` | Update an existing DNS zone's properties |
| `delete_dns_database_zone` | Delete a DNS zone and all its entries |
| `create_dns_entry` | Add a DNS record (A, AAAA, CNAME, MX, NS, PTR, TXT, SRV) to a zone |
| `update_dns_entry` | Update an existing DNS entry by zone name and entry ID |
| `delete_dns_entry` | Delete a DNS entry from a zone by entry ID |

### Network

| Tool | Description |
|---|---|
| `get_arp_table` | Get the ARP table (MAC-to-IP mappings) |

### High Availability

| Tool | Description |
|---|---|
| `get_ha_status` | Get HA cluster peer status |

### SNMP

| Tool | Description |
|---|---|
| `get_snmp_communities` | List SNMP community configurations |
| `get_snmp_sysinfo` | Get SNMP system information settings |
| `update_snmp_sysinfo` | Update SNMP system info (contact, location, description) |

### NTP

| Tool | Description |
|---|---|
| `get_ntp_settings` | Get NTP time synchronization settings |
| `update_ntp_settings` | Update NTP settings (sync, interval, server mode) |

### Automation

| Tool | Description |
|---|---|
| `get_automation_stitches` | List all automation stitches |
| `get_automation_stitch` | Get a specific automation stitch by name |
| `create_automation_stitch` | Create a new automation stitch |
| `update_automation_stitch` | Update an existing automation stitch |
| `delete_automation_stitch` | Delete an automation stitch by name |
| `get_automation_triggers` | List all automation triggers |
| `get_automation_actions` | List all automation actions |

### Virtual Wire Pairs

| Tool | Description |
|---|---|
| `get_virtual_wire_pairs` | List all virtual wire pairs |
| `create_virtual_wire_pair` | Create a new virtual wire pair |
| `delete_virtual_wire_pair` | Delete a virtual wire pair by name |

### VDOM Links

| Tool | Description |
|---|---|
| `get_vdom_links` | List all inter-VDOM links |
| `create_vdom_link` | Create a new inter-VDOM link |
| `delete_vdom_link` | Delete an inter-VDOM link by name |

### Session Helpers

| Tool | Description |
|---|---|
| `get_session_helpers` | List all session helper (ALG) configurations |
| `update_session_helper` | Update a session helper entry by ID |

### NetFlow

| Tool | Description |
|---|---|
| `get_netflow_settings` | Get NetFlow export configuration |
| `update_netflow_settings` | Update NetFlow export configuration |

### sFlow

| Tool | Description |
|---|---|
| `get_sflow_settings` | Get sFlow export configuration |
| `update_sflow_settings` | Update sFlow export configuration |

### FortiGuard

| Tool | Description |
|---|---|
| `get_fortiguard_settings` | Get FortiGuard update and filtering service settings |
| `update_fortiguard_settings` | Update FortiGuard settings |

### Security Fabric

| Tool | Description |
|---|---|
| `get_security_fabric_settings` | Get Security Fabric (CSF) configuration |
| `update_security_fabric_settings` | Update Security Fabric settings |

### Central Management

| Tool | Description |
|---|---|
| `get_central_management` | Get FortiManager central management settings |
| `update_central_management` | Update FortiManager central management settings |

### Link Monitor

| Tool | Description |
|---|---|
| `get_link_monitors` | List all WAN link monitors |
| `get_link_monitor` | Get a specific link monitor by name |
| `create_link_monitor` | Create a new link monitor |
| `update_link_monitor` | Update an existing link monitor |
| `delete_link_monitor` | Delete a link monitor by name |

### Object Tagging

| Tool | Description |
|---|---|
| `get_object_tags` | List all object tag categories |
| `create_object_tag` | Create a new object tag category |
| `delete_object_tag` | Delete an object tag category |

### Replacement Messages

| Tool | Description |
|---|---|
| `get_replacemsg_groups` | List all custom replacement message groups |

### Traffic Shaping

| Tool | Description |
|---|---|
| `get_traffic_shapers` | List all traffic shaper profiles |
| `get_traffic_shaping_policies` | List per-IP traffic shaper policies |

### Logging

| Tool | Description |
|---|---|
| `get_traffic_logs` | Get recent traffic (forward) logs |
| `get_event_logs` | Get recent system event logs |
| `get_security_logs` | Get recent IPS/UTM security logs |

### Log Settings

| Tool | Description |
|---|---|
| `get_log_settings` | Get global log configuration settings |
| `update_log_settings` | Update global log configuration settings |
| `get_log_event_filter` | Get log event filter (which event types are logged) |
| `update_log_event_filter` | Update log event filter |
| `get_log_threat_weight` | Get threat weight scoring configuration |
| `update_log_threat_weight` | Update threat weight scoring configuration |

### Syslog

| Tool | Description |
|---|---|
| `get_syslog_settings` | Get remote syslog server configuration |
| `update_syslog_settings` | Update remote syslog server settings |
| `get_syslog_filter` | Get syslog log filter settings |
| `update_syslog_filter` | Update syslog log filter settings |

### FortiAnalyzer

| Tool | Description |
|---|---|
| `get_fortianalyzer_settings` | Get FortiAnalyzer log forwarding configuration |
| `update_fortianalyzer_settings` | Update FortiAnalyzer log forwarding settings |
| `get_fortianalyzer_filter` | Get FortiAnalyzer log filter settings |
| `update_fortianalyzer_filter` | Update FortiAnalyzer log filter settings |

### Log Disk

| Tool | Description |
|---|---|
| `get_log_disk_settings` | Get local disk logging settings |
| `update_log_disk_settings` | Update local disk logging settings |
| `get_log_disk_filter` | Get local disk log filter settings |
| `update_log_disk_filter` | Update local disk log filter settings |

### FortiCloud Logging

| Tool | Description |
|---|---|
| `get_forticloud_log_settings` | Get FortiCloud log upload settings |
| `update_forticloud_log_settings` | Update FortiCloud log upload settings |

### Sessions

| Tool | Description |
|---|---|
| `get_session_count` | Get firewall session count summary |
| `get_firewall_sessions` | List active sessions with optional source IP filter |

### Switch Controller (FortiSwitch)

| Tool | Description |
|---|---|
| `get_managed_switches` | List all FortiSwitch managed switches |
| `get_managed_switch` | Get a specific managed switch by serial number |
| `update_managed_switch` | Update a managed switch configuration |
| `delete_managed_switch` | Delete (deauthorize) a managed switch |
| `get_switch_vlans` | List all switch controller VLANs |
| `create_switch_vlan` | Create a new switch controller VLAN |
| `delete_switch_vlan` | Delete a switch controller VLAN |
| `get_switch_stp_settings` | Get STP settings |
| `update_switch_stp_settings` | Update STP settings |
| `get_switch_qos_policies` | List all switch QoS policies |
| `get_switch_qos_dot1p_map` | List all 802.1p priority maps |
| `get_switch_qos_ip_dscp_map` | List all IP DSCP maps |

### Wireless Controller

| Tool | Description |
|---|---|
| `get_managed_aps` | List all managed FortiAP access points |
| `get_managed_ap` | Get a specific managed AP by ID |
| `update_managed_ap` | Update a managed AP configuration |
| `delete_managed_ap` | Delete (deauthorize) a managed AP |
| `get_wtp_profiles` | List all WTP (Wireless Termination Point) profiles |
| `get_wtp_profile` | Get a specific WTP profile |
| `get_wireless_ssids` | List all wireless SSIDs (VAPs) |
| `get_wireless_ssid` | Get a specific wireless SSID (VAP) |
| `create_wireless_ssid` | Create a new wireless SSID (VAP) |
| `update_wireless_ssid` | Update a wireless SSID (VAP) |
| `delete_wireless_ssid` | Delete a wireless SSID (VAP) |
| `get_wids_profiles` | List all Wireless IDS profiles |
| `get_wids_profile` | Get a specific Wireless IDS profile |

### WAN Optimization

| Tool | Description |
|---|---|
| `get_wanopt_profiles` | List all WAN optimization profiles |
| `get_wanopt_profile` | Get a specific WAN optimization profile |
| `create_wanopt_profile` | Create a WAN optimization profile (HTTP, FTP, CIFS, MAPI, TCP) |
| `update_wanopt_profile` | Update a WAN optimization profile |
| `delete_wanopt_profile` | Delete a WAN optimization profile |
| `get_wanopt_peers` | List all WAN optimization peers |
| `get_wanopt_peer` | Get a specific WAN optimization peer |
| `create_wanopt_peer` | Create a WAN optimization peer |
| `update_wanopt_peer` | Update a WAN optimization peer |
| `delete_wanopt_peer` | Delete a WAN optimization peer |
| `get_wanopt_auth_groups` | List all WAN optimization auth groups |
| `get_wanopt_auth_group` | Get a specific WAN optimization auth group |
| `create_wanopt_auth_group` | Create a WAN optimization auth group |
| `update_wanopt_auth_group` | Update a WAN optimization auth group |
| `delete_wanopt_auth_group` | Delete a WAN optimization auth group |
| `get_wanopt_cdn_rules` | List all WAN optimization CDN rules |
| `get_wanopt_cdn_rule` | Get a specific WAN optimization CDN rule |
| `create_wanopt_cdn_rule` | Create a WAN optimization CDN rule |
| `update_wanopt_cdn_rule` | Update a WAN optimization CDN rule |
| `delete_wanopt_cdn_rule` | Delete a WAN optimization CDN rule |
| `get_wanopt_cache_service` | Get WAN optimization cache service settings |
| `update_wanopt_cache_service` | Update WAN optimization cache service settings |
| `get_wanopt_webcache` | Get WAN optimization web cache settings |
| `update_wanopt_webcache` | Update WAN optimization web cache settings |
| `get_wanopt_remote_storage` | Get WAN optimization remote storage settings |
| `update_wanopt_remote_storage` | Update WAN optimization remote storage settings |
| `get_wanopt_settings` | Get global WAN optimization settings |
| `update_wanopt_settings` | Update global WAN optimization settings |

## VDOM Support

Most tools accept an optional `vdom` parameter to target a specific virtual domain. When omitted, the FortiGate uses its default VDOM (typically `root`).

## SSL/TLS Notes

FortiGate devices commonly use self-signed certificates. Set `FORTIGATE_VERIFY_SSL=false` to bypass certificate verification. This is expected in lab and many production environments.

## Project Structure

```
fortigate-mcp/
  src/
    index.ts              # MCP server - tool definitions and registration
    fortigate-client.ts   # FortiOS REST API client
  dist/                   # Compiled output (after build)
  package.json
  tsconfig.json
```

## License

MIT
