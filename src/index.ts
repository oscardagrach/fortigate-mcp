#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { FortigateClient } from './fortigate-client.js';

// Disable TLS verification for self-signed certs (common on Fortigate devices)
const verifySsl = process.env.FORTIGATE_VERIFY_SSL !== 'false';
if (!verifySsl) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

const host = process.env.FORTIGATE_HOST;
const port = parseInt(process.env.FORTIGATE_PORT || '443', 10);
const apiToken = process.env.FORTIGATE_API_TOKEN;

if (!host || !apiToken) {
  console.error('Error: FORTIGATE_HOST and FORTIGATE_API_TOKEN environment variables are required.');
  console.error('Optional: FORTIGATE_PORT (default: 443), FORTIGATE_VERIFY_SSL (default: true)');
  process.exit(1);
}

const client = new FortigateClient({ host, port, apiToken, verifySsl });

const server = new McpServer({
  name: 'fortigate-mcp',
  version: '1.0.0',
});

// Helper to format API responses as tool results
function result(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function errorResult(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: 'text' as const, text: `Error: ${message}` }], isError: true };
}

// ─── System Tools ──────────────────────────────────────────

server.tool('get_system_status', 'Get Fortigate system status including hostname, firmware version, serial number', {}, async () => {
  try {
    return result(await client.getSystemStatus());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_system_resources', 'Get CPU, memory, and disk usage statistics', {}, async () => {
  try {
    return result(await client.getSystemResources());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_system_performance', 'Get system performance metrics', {}, async () => {
  try {
    return result(await client.getSystemPerformance());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Interface Tools ───────────────────────────────────────

server.tool('get_interfaces', 'List all network interfaces with their configuration and status', {}, async () => {
  try {
    return result(await client.getInterfaces());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'get_interface',
  'Get details for a specific network interface',
  { name: z.string().describe('Interface name (e.g., port1, wan1, internal)') },
  async ({ name }) => {
    try {
      return result(await client.getInterface(name));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_interface',
  'Update a network interface configuration',
  {
    name: z.string().describe('Interface name (e.g., port1, wan1, internal)'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"ip": "192.168.1.1 255.255.255.0", "allowaccess": "ping https ssh", "alias": "LAN"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateInterface(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Firewall Policy Tools ─────────────────────────────────

server.tool(
  'get_firewall_policies',
  'List all firewall policies with source, destination, action, and service details',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getFirewallPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_firewall_policy',
  'Get a specific firewall policy by its ID',
  {
    id: z.number().describe('Policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getFirewallPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_firewall_policy',
  'Create a new firewall policy',
  {
    name: z.string().describe('Policy name'),
    srcintf: z.string().describe('Source interface (e.g., internal)'),
    dstintf: z.string().describe('Destination interface (e.g., wan1)'),
    srcaddr: z.string().describe('Source address object name (e.g., all)'),
    dstaddr: z.string().describe('Destination address object name (e.g., all)'),
    service: z.string().describe('Service name (e.g., ALL, HTTP, HTTPS)'),
    action: z.enum(['accept', 'deny']).describe('Policy action'),
    nat: z.boolean().optional().describe('Enable NAT (default: false)'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Policy comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, srcintf, dstintf, srcaddr, dstaddr, service, action, nat, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        name,
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        action,
        nat: nat ? 'enable' : 'disable',
        status: status || 'enable',
      };
      if (comments) policy.comments = comments;
      return result(await client.createFirewallPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_firewall_policy',
  'Update an existing firewall policy by ID',
  {
    id: z.number().describe('Policy ID to update'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"action": "deny", "status": "disable"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateFirewallPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_firewall_policy',
  'Delete a firewall policy by ID',
  {
    id: z.number().describe('Policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteFirewallPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Address Object Tools ──────────────────────────────────

server.tool(
  'get_addresses',
  'List all firewall address objects',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getAddresses(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_address',
  'Get a specific firewall address object by name',
  {
    name: z.string().describe('Address object name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getAddress(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_address',
  'Create a new firewall address object',
  {
    name: z.string().describe('Address object name'),
    type: z.enum(['ipmask', 'iprange', 'fqdn']).describe('Address type'),
    subnet: z.string().optional().describe('Subnet in CIDR notation (for ipmask type, e.g., 192.168.1.0/24)'),
    start_ip: z.string().optional().describe('Start IP (for iprange type)'),
    end_ip: z.string().optional().describe('End IP (for iprange type)'),
    fqdn: z.string().optional().describe('FQDN value (for fqdn type)'),
    comment: z.string().optional().describe('Comment'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, type, subnet, start_ip, end_ip, fqdn, comment, vdom }) => {
    try {
      const address: Record<string, unknown> = { name, type };
      if (type === 'ipmask' && subnet) {
        // Convert CIDR to space-separated format if needed
        address.subnet = subnet.replace('/', ' ');
      }
      if (type === 'iprange') {
        address['start-ip'] = start_ip;
        address['end-ip'] = end_ip;
      }
      if (type === 'fqdn' && fqdn) {
        address.fqdn = fqdn;
      }
      if (comment) address.comment = comment;
      return result(await client.createAddress(address, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_address',
  'Update an existing firewall address object by name',
  {
    name: z.string().describe('Address object name to update'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"subnet": "10.0.0.0 255.255.0.0", "comment": "updated"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateAddress(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_address',
  'Delete a firewall address object by name',
  {
    name: z.string().describe('Address object name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteAddress(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Address Group Tools ───────────────────────────────────

server.tool(
  'get_address_groups',
  'List all firewall address groups',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getAddressGroups(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Service Tools ─────────────────────────────────────────

server.tool(
  'get_services',
  'List all custom firewall service objects',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getServices(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Routing Tools ─────────────────────────────────────────

server.tool('get_routing_table', 'Get the active routing table (IPv4)', {}, async () => {
  try {
    return result(await client.getRoutingTable());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'get_static_routes',
  'List all configured static routes',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getStaticRoutes(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_static_route',
  'Create a new static route',
  {
    dst: z.string().describe('Destination subnet (e.g., 10.0.0.0 255.255.255.0 or 10.0.0.0/24)'),
    gateway: z.string().describe('Gateway IP address'),
    device: z.string().describe('Outgoing interface name (e.g., wan1, port1)'),
    distance: z.number().optional().describe('Administrative distance (default: 10)'),
    weight: z.number().optional().describe('Route weight (default: 0)'),
    priority: z.number().optional().describe('Route priority (default: 0)'),
    status: z.enum(['enable', 'disable']).optional().describe('Route status'),
    comment: z.string().optional().describe('Comment'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ dst, gateway, device, distance, weight, priority, status, comment, vdom }) => {
    try {
      const route: Record<string, unknown> = { dst, gateway, device };
      if (distance !== undefined) route.distance = distance;
      if (weight !== undefined) route.weight = weight;
      if (priority !== undefined) route.priority = priority;
      if (status) route.status = status;
      if (comment) route.comment = comment;
      return result(await client.createStaticRoute(route, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_static_route',
  'Update an existing static route by ID',
  {
    id: z.number().describe('Static route ID'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"gateway": "10.0.0.1", "distance": 20})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateStaticRoute(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_static_route',
  'Delete a static route by ID',
  {
    id: z.number().describe('Static route ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteStaticRoute(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── VPN Tools ─────────────────────────────────────────────

server.tool('get_ipsec_vpn_status', 'Get IPsec VPN tunnel status and statistics', {}, async () => {
  try {
    return result(await client.getIPsecVpnStatus());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_ssl_vpn_status', 'Get SSL VPN sessions and connected users', {}, async () => {
  try {
    return result(await client.getSslVpnStatus());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── DHCP Tools ────────────────────────────────────────────

server.tool('get_dhcp_leases', 'List all DHCP leases across interfaces', {}, async () => {
  try {
    return result(await client.getDhcpLeases());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Network Tools ─────────────────────────────────────────

server.tool('get_arp_table', 'Get the ARP table showing MAC-to-IP mappings', {}, async () => {
  try {
    return result(await client.getArpTable());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_dns_settings', 'Get DNS server configuration', {}, async () => {
  try {
    return result(await client.getDnsSettings());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'update_dns_settings',
  'Update DNS server configuration (primary, secondary, domain, etc.)',
  {
    primary: z.string().optional().describe('Primary DNS server IP'),
    secondary: z.string().optional().describe('Secondary DNS server IP'),
    domain: z.string().optional().describe('Local domain name'),
  },
  async ({ primary, secondary, domain }) => {
    try {
      const settings: Record<string, unknown> = {};
      if (primary) settings.primary = primary;
      if (secondary) settings.secondary = secondary;
      if (domain) settings.domain = domain;
      return result(await client.updateDnsSettings(settings));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── HA Tools ──────────────────────────────────────────────

server.tool('get_ha_status', 'Get High Availability cluster peer status', {}, async () => {
  try {
    return result(await client.getHaStatus());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── User Tools ────────────────────────────────────────────

server.tool(
  'get_local_users',
  'List local user accounts',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getLocalUsers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_user_groups',
  'List user groups',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getUserGroups(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Log Tools ─────────────────────────────────────────────

server.tool(
  'get_traffic_logs',
  'Get recent traffic (forward) logs from memory',
  {
    rows: z.number().optional().default(20).describe('Number of log entries to retrieve (default: 20)'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ rows, vdom }) => {
    try {
      return result(await client.getTrafficLogs(rows, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_event_logs',
  'Get recent system event logs from memory',
  {
    rows: z.number().optional().default(20).describe('Number of log entries to retrieve (default: 20)'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ rows, vdom }) => {
    try {
      return result(await client.getEventLogs(rows, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_security_logs',
  'Get recent IPS/UTM security logs from memory',
  {
    rows: z.number().optional().default(20).describe('Number of log entries to retrieve (default: 20)'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ rows, vdom }) => {
    try {
      return result(await client.getSecurityLogs(rows, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Session Tools ─────────────────────────────────────────

server.tool('get_session_count', 'Get firewall session count summary', {}, async () => {
  try {
    return result(await client.getSessionCount());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Firmware Tools ────────────────────────────────────────

server.tool('get_firmware_versions', 'Check available firmware versions and current version', {}, async () => {
  try {
    return result(await client.getFirmwareVersions());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Certificate Tools ─────────────────────────────────────

server.tool('get_certificates', 'List installed local certificates', {}, async () => {
  try {
    return result(await client.getCertificates());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Config Backup ─────────────────────────────────────────

server.tool(
  'get_config_backup',
  'Download the full configuration backup',
  { vdom: z.string().optional().describe('Specific VDOM to backup (omit for global)') },
  async ({ vdom }) => {
    try {
      return result(await client.getConfigBackup(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Firewall VIP (Virtual IP / DNAT) ──────────────────────

server.tool(
  'get_vips',
  'List all firewall virtual IP (VIP/DNAT) objects',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getVips(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_vip',
  'Get a specific firewall virtual IP (VIP) object by name',
  {
    name: z.string().describe('VIP object name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getVip(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_vip',
  'Create a firewall virtual IP (VIP) for DNAT / port forwarding',
  {
    name: z.string().describe('VIP name'),
    extip: z.string().describe('External IP address or range (e.g., 203.0.113.10)'),
    mappedip: z.string().describe('Mapped internal IP address or range (e.g., 192.168.1.10)'),
    extintf: z.string().optional().describe('External interface (default: any)'),
    portforward: z.boolean().optional().describe('Enable port forwarding'),
    extport: z.string().optional().describe('External port range (e.g., 8080 or 80-443)'),
    mappedport: z.string().optional().describe('Mapped port range (e.g., 80 or 80-443)'),
    protocol: z.enum(['tcp', 'udp', 'sctp', 'icmp']).optional().describe('Protocol for port forwarding'),
    comment: z.string().optional().describe('Comment'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, extip, mappedip, extintf, portforward, extport, mappedport, protocol, comment, vdom }) => {
    try {
      const vip: Record<string, unknown> = {
        name,
        extip,
        mappedip: [{ range: mappedip }],
        extintf: extintf || 'any',
      };
      if (portforward) {
        vip.portforward = 'enable';
        if (extport) vip.extport = extport;
        if (mappedport) vip.mappedport = mappedport;
        if (protocol) vip.protocol = protocol;
      }
      if (comment) vip.comment = comment;
      return result(await client.createVip(vip, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_vip',
  'Delete a firewall virtual IP (VIP) object by name',
  {
    name: z.string().describe('VIP object name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteVip(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── IP Pools (SNAT) ──────────────────────────────────────────

server.tool(
  'get_ip_pools',
  'List all firewall IP pools used for source NAT',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getIpPools(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Service Groups ───────────────────────────────────────────

server.tool(
  'get_service_groups',
  'List all firewall service groups',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getServiceGroups(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Firewall Schedules ───────────────────────────────────────

server.tool(
  'get_schedules_recurring',
  'List all recurring firewall schedules',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSchedulesRecurring(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_schedules_onetime',
  'List all one-time firewall schedules',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSchedulesOnetime(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Zones ────────────────────────────────────────────────────

server.tool(
  'get_zones',
  'List all system zones and their interface members',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getZones(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── SD-WAN ───────────────────────────────────────────────────

server.tool(
  'get_sdwan_config',
  'Get SD-WAN configuration including members, health checks, and rules',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSdwan(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool('get_sdwan_health_check', 'Get SD-WAN health check status for all members', {}, async () => {
  try {
    return result(await client.getSdwanHealthCheck());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_sdwan_members', 'Get SD-WAN member interface status and statistics', {}, async () => {
  try {
    return result(await client.getSdwanMembers());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── Security Profile Tools ──────────────────────────────────

server.tool(
  'get_webfilter_profiles',
  'List all web filter profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getWebFilterProfiles(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_antivirus_profiles',
  'List all antivirus profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getAntivirusProfiles(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_ips_sensors',
  'List all IPS (Intrusion Prevention System) sensor profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getIpsSensors(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_application_lists',
  'List all application control profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getApplicationLists(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_dnsfilter_profiles',
  'List all DNS filter profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getDnsFilterProfiles(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_ssl_ssh_profiles',
  'List all SSL/SSH inspection profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSslSshProfiles(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Dynamic Routing Tools ───────────────────────────────────

server.tool(
  'get_bgp_config',
  'Get BGP router configuration including neighbors and networks',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getBgpConfig(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool('get_bgp_neighbors', 'Get BGP neighbor/peer status and learned paths', {}, async () => {
  try {
    return result(await client.getBgpNeighbors());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'get_ospf_config',
  'Get OSPF router configuration including areas and interfaces',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getOspfConfig(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool('get_ospf_neighbors', 'Get OSPF neighbor adjacency status', {}, async () => {
  try {
    return result(await client.getOspfNeighbors());
  } catch (e) {
    return errorResult(e);
  }
});

// ─── SNMP Tools ───────────────────────────────────────────────

server.tool('get_snmp_communities', 'List SNMP community configurations', {}, async () => {
  try {
    return result(await client.getSnmpCommunities());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_snmp_sysinfo', 'Get SNMP system information settings (contact, location, description)', {}, async () => {
  try {
    return result(await client.getSnmpSysinfo());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'update_snmp_sysinfo',
  'Update SNMP system information (contact, location, description)',
  {
    status: z.enum(['enable', 'disable']).optional().describe('Enable or disable SNMP'),
    description: z.string().optional().describe('System description'),
    contact_info: z.string().optional().describe('Contact information'),
    location: z.string().optional().describe('System location'),
  },
  async ({ status, description, contact_info, location }) => {
    try {
      const settings: Record<string, unknown> = {};
      if (status) settings.status = status;
      if (description) settings.description = description;
      if (contact_info) settings['contact-info'] = contact_info;
      if (location) settings.location = location;
      return result(await client.updateSnmpSysinfo(settings));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── System (additional) ─────────────────────────────────────

server.tool('get_ntp_settings', 'Get NTP time synchronization settings', {}, async () => {
  try {
    return result(await client.getNtpSettings());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'update_ntp_settings',
  'Update NTP time synchronization settings',
  {
    ntpsync: z.enum(['enable', 'disable']).optional().describe('Enable/disable NTP sync'),
    server_mode: z.enum(['enable', 'disable']).optional().describe('Enable/disable NTP server mode'),
    source_ip: z.string().optional().describe('Source IP for NTP packets'),
    syncinterval: z.number().optional().describe('NTP sync interval in minutes'),
  },
  async ({ ntpsync, server_mode, source_ip, syncinterval }) => {
    try {
      const settings: Record<string, unknown> = {};
      if (ntpsync) settings.ntpsync = ntpsync;
      if (server_mode) settings['server-mode'] = server_mode;
      if (source_ip) settings['source-ip'] = source_ip;
      if (syncinterval !== undefined) settings.syncinterval = syncinterval;
      return result(await client.updateNtpSettings(settings));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool('get_vdoms', 'List all virtual domains (VDOMs)', {}, async () => {
  try {
    return result(await client.getVdoms());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_admins', 'List system administrator accounts', {}, async () => {
  try {
    return result(await client.getAdmins());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_admin_profiles', 'List admin access profiles (permissions)', {}, async () => {
  try {
    return result(await client.getAdminProfiles());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_global_settings', 'Get system global settings (admin port, timezone, language, etc.)', {}, async () => {
  try {
    return result(await client.getGlobalSettings());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'update_global_settings',
  'Update system global settings (hostname, timezone, admin ports, etc.)',
  {
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of global settings to update (e.g., {"hostname": "FW01", "timezone": "US/Eastern", "admin-sport": 8443})'),
  },
  async ({ updates }) => {
    try {
      return result(await client.updateGlobalSettings(updates));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── DHCP Server Tools ───────────────────────────────────────

server.tool(
  'get_dhcp_servers',
  'List all DHCP server configurations',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getDhcpServers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── DNS Database Tools ──────────────────────────────────────

server.tool(
  'get_dns_database',
  'List DNS database zones (local DNS entries)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getDnsDatabase(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Traffic Shaping Tools ───────────────────────────────────

server.tool(
  'get_traffic_shapers',
  'List all traffic shaper profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getTrafficShapers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_traffic_shaping_policies',
  'List per-IP traffic shaper policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getTrafficShapingPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Monitor (additional) ────────────────────────────────────

server.tool('get_license_status', 'Get FortiGuard license and subscription status', {}, async () => {
  try {
    return result(await client.getLicenseStatus());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_interface_stats', 'Get real-time interface traffic statistics and link status', {}, async () => {
  try {
    return result(await client.getInterfaceStats());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_banned_users', 'List currently banned user IPs', {}, async () => {
  try {
    return result(await client.getBannedUsers());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'get_firewall_sessions',
  'List active firewall sessions with optional source IP filter',
  {
    count: z.number().optional().default(20).describe('Number of sessions to retrieve (default: 20)'),
    source_ip: z.string().optional().describe('Filter by source IP address'),
  },
  async ({ count, source_ip }) => {
    try {
      return result(await client.getFirewallSessionList(count, source_ip));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── VPN (additional) ────────────────────────────────────────

server.tool(
  'get_ipsec_phase1',
  'List IPsec VPN Phase 1 interface configurations',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getIpsecPhase1(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_ipsec_phase2',
  'List IPsec VPN Phase 2 interface configurations',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getIpsecPhase2(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_ssl_vpn_settings',
  'Get SSL VPN server settings (portal, tunnel, authentication)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSslVpnSettings(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Start Server ──────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Fortigate MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
