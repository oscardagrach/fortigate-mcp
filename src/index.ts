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

server.tool(
  'get_sdwan_sla_log',
  'Get SD-WAN SLA performance log for a specific health check (latency, jitter, packet loss over time)',
  { sla: z.string().describe('Health check name (e.g., Default_DNS, Default_Google)') },
  async ({ sla }) => {
    try {
      return result(await client.getSdwanSlaLog(sla));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_sdwan_zones',
  'List SD-WAN zone configurations and member interfaces',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSdwanZones(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_sdwan_config',
  'Update SD-WAN configuration (status, load-balance-mode, health checks, etc.)',
  {
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs to update (e.g., {"status": "enable", "load-balance-mode": "source-ip-based"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ updates, vdom }) => {
    try {
      return result(await client.updateSdwan(updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Firewall Policy Statistics ─────────────────────────────

server.tool('get_policy_stats', 'Get firewall policy hit counts, byte/packet statistics, and last-used timestamps', {}, async () => {
  try {
    return result(await client.getPolicyStats());
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

server.tool('get_bgp_paths', 'Get BGP learned/advertised route paths', {}, async () => {
  try {
    return result(await client.getBgpPaths());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool('get_bgp_neighbors_status', 'Get BGP neighbor status (state, uptime, prefixes received)', {}, async () => {
  try {
    return result(await client.getBgpNeighborsStatus());
  } catch (e) {
    return errorResult(e);
  }
});

server.tool(
  'get_bgp_networks',
  'List BGP network entries being advertised',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getBgpNetworks(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_bgp_redistribute',
  'Get BGP route redistribution settings (connected, static, OSPF, etc.)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getBgpRedistribute(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_bgp_config',
  'Update BGP configuration (router-id, AS number, neighbors, networks, etc.)',
  {
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs to update (e.g., {"as": 65001, "router-id": "10.0.0.1"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ updates, vdom }) => {
    try {
      return result(await client.updateBgpConfig(updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Route Policy Tools ─────────────────────────────────────

server.tool(
  'get_prefix_lists',
  'List all router prefix lists',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getPrefixLists(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_route_maps',
  'List all router route maps',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getRouteMaps(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_community_lists',
  'List all BGP community lists',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getCommunityLists(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

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

server.tool(
  'update_ospf_config',
  'Update OSPF configuration (router-id, areas, redistribute, etc.)',
  {
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs to update (e.g., {"router-id": "10.0.0.1", "default-metric": 10})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ updates, vdom }) => {
    try {
      return result(await client.updateOspfConfig(updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

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
  'List all DNS database zones (local DNS entries)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getDnsDatabase(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_dns_database_zone',
  'Get a specific DNS database zone by name, including all its DNS entries',
  {
    name: z.string().describe('DNS zone name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getDnsDatabaseZone(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_dns_database_zone',
  'Create a new DNS database zone',
  {
    name: z.string().describe('DNS zone name'),
    domain: z.string().describe('Domain name for the zone (e.g., example.com)'),
    type: z.enum(['master', 'slave', 'forwarder']).describe('Zone type'),
    view: z.enum(['shadow', 'public', 'shadow-public']).optional().describe('Zone view (default: shadow)'),
    ip_master: z.string().optional().describe('IP of master DNS server (required for slave zones)'),
    authoritative: z.enum(['enable', 'disable']).optional().describe('Enable/disable authoritative for this zone'),
    source_ip: z.string().optional().describe('Source IP for forwarding/transfer'),
    ttl: z.number().optional().describe('Default TTL for the zone (seconds)'),
    dns_entries: z
      .array(
        z.object({
          type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV']).describe('Record type'),
          hostname: z.string().describe('Hostname'),
          ip: z.string().optional().describe('IPv4 address (for A records)'),
          ipv6: z.string().optional().describe('IPv6 address (for AAAA records)'),
          canonical_name: z.string().optional().describe('Canonical name (for CNAME records)'),
          preference: z.number().optional().describe('MX preference value'),
          ttl: z.number().optional().describe('TTL for this entry (seconds)'),
          status: z.enum(['enable', 'disable']).optional().describe('Entry status'),
        })
      )
      .optional()
      .describe('Initial DNS entries to create with the zone'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, domain, type, view, ip_master, authoritative, source_ip, ttl, dns_entries, vdom }) => {
    try {
      const zone: Record<string, unknown> = { name, domain, type };
      if (view) zone.view = view;
      if (ip_master) zone['ip-master'] = ip_master;
      if (authoritative) zone.authoritative = authoritative;
      if (source_ip) zone['source-ip'] = source_ip;
      if (ttl !== undefined) zone.ttl = ttl;
      if (dns_entries) {
        zone['dns-entry'] = dns_entries.map((entry) => {
          const e: Record<string, unknown> = { type: entry.type, hostname: entry.hostname };
          if (entry.ip) e.ip = entry.ip;
          if (entry.ipv6) e.ipv6 = entry.ipv6;
          if (entry.canonical_name) e['canonical-name'] = entry.canonical_name;
          if (entry.preference !== undefined) e.preference = entry.preference;
          if (entry.ttl !== undefined) e.ttl = entry.ttl;
          if (entry.status) e.status = entry.status;
          return e;
        });
      }
      return result(await client.createDnsDatabaseZone(zone, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_dns_database_zone',
  'Update an existing DNS database zone',
  {
    name: z.string().describe('DNS zone name to update'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"domain": "new.example.com", "ttl": 3600})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateDnsDatabaseZone(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_dns_database_zone',
  'Delete a DNS database zone and all its entries',
  {
    name: z.string().describe('DNS zone name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteDnsDatabaseZone(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_dns_entry',
  'Add a DNS entry (record) to an existing DNS database zone',
  {
    zone_name: z.string().describe('DNS zone name to add the entry to'),
    type: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT', 'SRV']).describe('DNS record type'),
    hostname: z.string().describe('Hostname for the entry'),
    ip: z.string().optional().describe('IPv4 address (for A records)'),
    ipv6: z.string().optional().describe('IPv6 address (for AAAA records)'),
    canonical_name: z.string().optional().describe('Canonical name (for CNAME records)'),
    preference: z.number().optional().describe('MX preference value'),
    ttl: z.number().optional().describe('TTL for this entry (seconds)'),
    status: z.enum(['enable', 'disable']).optional().describe('Entry status'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ zone_name, type, hostname, ip, ipv6, canonical_name, preference, ttl, status, vdom }) => {
    try {
      const entry: Record<string, unknown> = { type, hostname };
      if (ip) entry.ip = ip;
      if (ipv6) entry.ipv6 = ipv6;
      if (canonical_name) entry['canonical-name'] = canonical_name;
      if (preference !== undefined) entry.preference = preference;
      if (ttl !== undefined) entry.ttl = ttl;
      if (status) entry.status = status;
      return result(await client.createDnsEntry(zone_name, entry, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_dns_entry',
  'Update an existing DNS entry in a DNS database zone',
  {
    zone_name: z.string().describe('DNS zone name containing the entry'),
    entry_id: z.number().describe('DNS entry ID to update (use get_dns_database_zone to find IDs)'),
    updates: z
      .record(z.unknown())
      .describe('Key-value pairs of fields to update (e.g., {"ip": "10.0.0.2", "ttl": 600})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ zone_name, entry_id, updates, vdom }) => {
    try {
      return result(await client.updateDnsEntry(zone_name, entry_id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_dns_entry',
  'Delete a DNS entry from a DNS database zone',
  {
    zone_name: z.string().describe('DNS zone name containing the entry'),
    entry_id: z.number().describe('DNS entry ID to delete (use get_dns_database_zone to find IDs)'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ zone_name, entry_id, vdom }) => {
    try {
      return result(await client.deleteDnsEntry(zone_name, entry_id, vdom));
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

// ─── IPv6 Firewall Policy Tools ─────────────────────────────

server.tool(
  'get_firewall_policies6',
  'List all IPv6 firewall policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getFirewallPolicies6(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_firewall_policy6',
  'Get a specific IPv6 firewall policy by ID',
  {
    id: z.number().describe('Policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getFirewallPolicy6(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_firewall_policy6',
  'Create a new IPv6 firewall policy',
  {
    name: z.string().describe('Policy name'),
    srcintf: z.string().describe('Source interface (e.g., internal)'),
    dstintf: z.string().describe('Destination interface (e.g., wan1)'),
    srcaddr: z.string().describe('Source IPv6 address object name (e.g., all)'),
    dstaddr: z.string().describe('Destination IPv6 address object name (e.g., all)'),
    service: z.string().describe('Service name (e.g., ALL, HTTP, HTTPS)'),
    action: z.enum(['accept', 'deny']).describe('Policy action'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Policy comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, srcintf, dstintf, srcaddr, dstaddr, service, action, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        name,
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        action,
        status: status || 'enable',
      };
      if (comments) policy.comments = comments;
      return result(await client.createFirewallPolicy6(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_firewall_policy6',
  'Update an existing IPv6 firewall policy by ID',
  {
    id: z.number().describe('Policy ID to update'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"action": "deny", "status": "disable"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateFirewallPolicy6(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_firewall_policy6',
  'Delete an IPv6 firewall policy by ID',
  {
    id: z.number().describe('Policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteFirewallPolicy6(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Central SNAT Tools ────────────────────────────────────

server.tool(
  'get_central_snat_map',
  'List all central SNAT map entries',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getCentralSnatMap(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_central_snat_entry',
  'Get a specific central SNAT entry by ID',
  {
    id: z.number().describe('Central SNAT entry ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getCentralSnatEntry(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_central_snat_entry',
  'Create a new central SNAT map entry',
  {
    srcintf: z.string().describe('Source interface'),
    dstintf: z.string().describe('Destination interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination address object name'),
    nat: z.enum(['enable', 'disable']).describe('Enable/disable source NAT'),
    nat_ippool: z.string().optional().describe('IP pool name for NAT (if nat is enabled)'),
    comments: z.string().optional().describe('Comments'),
    status: z.enum(['enable', 'disable']).optional().describe('Entry status'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ srcintf, dstintf, srcaddr, dstaddr, nat, nat_ippool, comments, status, vdom }) => {
    try {
      const entry: Record<string, unknown> = {
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        'orig-addr': [{ name: srcaddr }],
        'dst-addr': [{ name: dstaddr }],
        nat,
        status: status || 'enable',
      };
      if (nat_ippool) entry['nat-ippool'] = [{ name: nat_ippool }];
      if (comments) entry.comments = comments;
      return result(await client.createCentralSnatEntry(entry, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_central_snat_entry',
  'Update an existing central SNAT entry by ID',
  {
    id: z.number().describe('Central SNAT entry ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateCentralSnatEntry(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_central_snat_entry',
  'Delete a central SNAT entry by ID',
  {
    id: z.number().describe('Central SNAT entry ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteCentralSnatEntry(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── DoS Policy Tools ──────────────────────────────────────

server.tool(
  'get_dos_policies',
  'List all DoS protection policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getDosPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_dos_policy',
  'Get a specific DoS policy by ID',
  {
    id: z.number().describe('DoS policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getDosPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_dos_policy',
  'Create a new DoS protection policy',
  {
    srcintf: z.string().describe('Incoming interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination address object name'),
    service: z.string().describe('Service name'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ srcintf, srcaddr, dstaddr, service, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        interface: [{ name: srcintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        status: status || 'enable',
      };
      if (comments) policy.comments = comments;
      return result(await client.createDosPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_dos_policy',
  'Update an existing DoS policy by ID',
  {
    id: z.number().describe('DoS policy ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateDosPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_dos_policy',
  'Delete a DoS policy by ID',
  {
    id: z.number().describe('DoS policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteDosPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Multicast Policy Tools ────────────────────────────────

server.tool(
  'get_multicast_policies',
  'List all multicast firewall policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getMulticastPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_multicast_policy',
  'Get a specific multicast policy by ID',
  {
    id: z.number().describe('Multicast policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getMulticastPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_multicast_policy',
  'Create a new multicast firewall policy',
  {
    srcintf: z.string().describe('Source interface'),
    dstintf: z.string().describe('Destination interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination multicast address object name'),
    action: z.enum(['accept', 'deny']).describe('Policy action'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ srcintf, dstintf, srcaddr, dstaddr, action, status, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        action,
        status: status || 'enable',
      };
      return result(await client.createMulticastPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_multicast_policy',
  'Update an existing multicast policy by ID',
  {
    id: z.number().describe('Multicast policy ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateMulticastPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_multicast_policy',
  'Delete a multicast policy by ID',
  {
    id: z.number().describe('Multicast policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteMulticastPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Proxy Policy Tools ────────────────────────────────────

server.tool(
  'get_proxy_policies',
  'List all explicit/transparent proxy policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getProxyPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_proxy_policy',
  'Get a specific proxy policy by ID',
  {
    id: z.number().describe('Proxy policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getProxyPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_proxy_policy',
  'Create a new proxy policy',
  {
    proxy: z.enum(['explicit-web', 'transparent-web', 'ftp', 'ssh', 'ssh-tunnel', 'wanopt']).describe('Proxy type'),
    srcintf: z.string().describe('Source interface'),
    dstintf: z.string().describe('Destination interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination address object name'),
    service: z.string().describe('Service name'),
    action: z.enum(['accept', 'deny']).describe('Policy action'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ proxy, srcintf, dstintf, srcaddr, dstaddr, service, action, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        proxy,
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        action,
        status: status || 'enable',
      };
      if (comments) policy.comments = comments;
      return result(await client.createProxyPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_proxy_policy',
  'Update an existing proxy policy by ID',
  {
    id: z.number().describe('Proxy policy ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateProxyPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_proxy_policy',
  'Delete a proxy policy by ID',
  {
    id: z.number().describe('Proxy policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteProxyPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Local-in Policy Tools ─────────────────────────────────

server.tool(
  'get_local_in_policies',
  'List all local-in policies (traffic destined to the FortiGate itself)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getLocalInPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_local_in_policy',
  'Get a specific local-in policy by ID',
  {
    id: z.number().describe('Local-in policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getLocalInPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_local_in_policy',
  'Create a new local-in policy (controls traffic to the FortiGate itself)',
  {
    srcintf: z.string().describe('Source interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination address object name'),
    service: z.string().describe('Service name'),
    action: z.enum(['accept', 'deny']).describe('Policy action'),
    schedule: z.string().optional().default('always').describe('Schedule name (default: always)'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ srcintf, srcaddr, dstaddr, service, action, schedule, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        intf: [{ name: srcintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        action,
        schedule,
        status: status || 'enable',
      };
      if (comments) policy.comments = comments;
      return result(await client.createLocalInPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_local_in_policy',
  'Update an existing local-in policy by ID',
  {
    id: z.number().describe('Local-in policy ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateLocalInPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_local_in_policy',
  'Delete a local-in policy by ID',
  {
    id: z.number().describe('Local-in policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteLocalInPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── IPv6 Address Object Tools ──────────────────────────────

server.tool(
  'get_addresses6',
  'List all IPv6 firewall address objects',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getAddresses6(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_address6',
  'Get a specific IPv6 address object by name',
  {
    name: z.string().describe('IPv6 address object name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getAddress6(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_address6',
  'Create a new IPv6 firewall address object',
  {
    name: z.string().describe('Address object name'),
    ip6: z.string().describe('IPv6 address/prefix (e.g., 2001:db8::/32)'),
    comment: z.string().optional().describe('Comment'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, ip6, comment, vdom }) => {
    try {
      const address: Record<string, unknown> = { name, ip6 };
      if (comment) address.comment = comment;
      return result(await client.createAddress6(address, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_address6',
  'Update an existing IPv6 address object by name',
  {
    name: z.string().describe('IPv6 address object name'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"ip6": "2001:db8:1::/48", "comment": "updated"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateAddress6(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_address6',
  'Delete an IPv6 address object by name',
  {
    name: z.string().describe('IPv6 address object name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteAddress6(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── IPv6 Address Group Tools ───────────────────────────────

server.tool(
  'get_address_groups6',
  'List all IPv6 firewall address groups',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getAddressGroups6(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Multicast Address Tools ────────────────────────────────

server.tool(
  'get_multicast_addresses',
  'List all firewall multicast address objects',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getMulticastAddresses(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Internet Service Tools ────────────────────────────────

server.tool(
  'get_internet_services',
  'List all predefined internet service objects (used in policies for well-known services)',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getInternetServices(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Service Category Tools ────────────────────────────────

server.tool(
  'get_service_categories',
  'List all firewall service categories',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getServiceCategories(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── VIP Group Tools ───────────────────────────────────────

server.tool(
  'get_vip_groups',
  'List all firewall virtual IP groups',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getVipGroups(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── IPv6 IP Pool Tools ────────────────────────────────────

server.tool(
  'get_ip_pools6',
  'List all IPv6 IP pools for source NAT',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getIpPools6(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Shaping Profile Tools ─────────────────────────────────

server.tool(
  'get_shaping_profiles',
  'List all firewall traffic shaping profiles',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getShapingProfiles(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── Shaping Policy Tools ──────────────────────────────────

server.tool(
  'get_shaping_policies',
  'List all firewall traffic shaping policies',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getShapingPolicies(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_shaping_policy',
  'Get a specific shaping policy by ID',
  {
    id: z.number().describe('Shaping policy ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getShapingPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_shaping_policy',
  'Create a new traffic shaping policy',
  {
    srcintf: z.string().describe('Source interface'),
    dstintf: z.string().describe('Destination interface'),
    srcaddr: z.string().describe('Source address object name'),
    dstaddr: z.string().describe('Destination address object name'),
    service: z.string().describe('Service name'),
    traffic_shaper: z.string().optional().describe('Traffic shaper profile name for guaranteed bandwidth'),
    traffic_shaper_reverse: z.string().optional().describe('Reverse traffic shaper profile name'),
    status: z.enum(['enable', 'disable']).optional().describe('Policy status'),
    comments: z.string().optional().describe('Comments'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ srcintf, dstintf, srcaddr, dstaddr, service, traffic_shaper, traffic_shaper_reverse, status, comments, vdom }) => {
    try {
      const policy: Record<string, unknown> = {
        srcintf: [{ name: srcintf }],
        dstintf: [{ name: dstintf }],
        srcaddr: [{ name: srcaddr }],
        dstaddr: [{ name: dstaddr }],
        service: [{ name: service }],
        status: status || 'enable',
      };
      if (traffic_shaper) policy['traffic-shaper'] = traffic_shaper;
      if (traffic_shaper_reverse) policy['traffic-shaper-reverse'] = traffic_shaper_reverse;
      if (comments) policy.comments = comments;
      return result(await client.createShapingPolicy(policy, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_shaping_policy',
  'Update an existing shaping policy by ID',
  {
    id: z.number().describe('Shaping policy ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateShapingPolicy(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_shaping_policy',
  'Delete a shaping policy by ID',
  {
    id: z.number().describe('Shaping policy ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteShapingPolicy(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── LDAP Server Tools ─────────────────────────────────────

server.tool(
  'get_ldap_servers',
  'List all configured LDAP server connections',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getLdapServers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_ldap_server',
  'Get a specific LDAP server configuration by name',
  {
    name: z.string().describe('LDAP server name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getLdapServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_ldap_server',
  'Create a new LDAP server connection',
  {
    name: z.string().describe('LDAP server name'),
    server: z.string().describe('LDAP server hostname or IP address'),
    port: z.number().optional().default(389).describe('LDAP server port (default: 389, use 636 for LDAPS)'),
    cnid: z.string().optional().default('cn').describe('Common name identifier (default: cn)'),
    dn: z.string().describe('Distinguished name used to look up entries (e.g., dc=example,dc=com)'),
    type: z.enum(['simple', 'anonymous', 'regular']).optional().default('simple').describe('Authentication type'),
    username: z.string().optional().describe('Bind DN username for authenticated lookups'),
    password: z.string().optional().describe('Bind password'),
    secure: z.enum(['disable', 'starttls', 'ldaps']).optional().default('disable').describe('SSL/TLS mode'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, server: ldapServer, port, cnid, dn, type, username, password, secure, vdom }) => {
    try {
      const ldap: Record<string, unknown> = { name, server: ldapServer, port, cnid, dn, type, secure };
      if (username) ldap.username = username;
      if (password) ldap.password = password;
      return result(await client.createLdapServer(ldap, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_ldap_server',
  'Update an existing LDAP server configuration',
  {
    name: z.string().describe('LDAP server name'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"server": "10.0.0.5", "secure": "ldaps", "port": 636})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateLdapServer(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_ldap_server',
  'Delete an LDAP server configuration by name',
  {
    name: z.string().describe('LDAP server name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteLdapServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── RADIUS Server Tools ───────────────────────────────────

server.tool(
  'get_radius_servers',
  'List all configured RADIUS server connections',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getRadiusServers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_radius_server',
  'Get a specific RADIUS server configuration by name',
  {
    name: z.string().describe('RADIUS server name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getRadiusServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_radius_server',
  'Create a new RADIUS server connection',
  {
    name: z.string().describe('RADIUS server name'),
    server: z.string().describe('RADIUS server hostname or IP address'),
    secret: z.string().describe('RADIUS shared secret'),
    secondary_server: z.string().optional().describe('Secondary RADIUS server hostname or IP'),
    secondary_secret: z.string().optional().describe('Secondary RADIUS shared secret'),
    auth_type: z.enum(['auto', 'ms_chap_v2', 'ms_chap', 'chap', 'pap']).optional().default('auto').describe('Authentication protocol'),
    nas_ip: z.string().optional().describe('NAS IP address for RADIUS communication'),
    radius_port: z.number().optional().default(1812).describe('RADIUS authentication port (default: 1812)'),
    acct_interim_interval: z.number().optional().describe('RADIUS accounting interim interval in seconds'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, server: radiusServer, secret, secondary_server, secondary_secret, auth_type, nas_ip, radius_port, acct_interim_interval, vdom }) => {
    try {
      const radius: Record<string, unknown> = { name, server: radiusServer, secret };
      if (auth_type) radius['auth-type'] = auth_type;
      if (nas_ip) radius['nas-ip'] = nas_ip;
      if (radius_port) radius['radius-port'] = radius_port;
      if (secondary_server) radius['secondary-server'] = secondary_server;
      if (secondary_secret) radius['secondary-secret'] = secondary_secret;
      if (acct_interim_interval) radius['acct-interim-interval'] = acct_interim_interval;
      return result(await client.createRadiusServer(radius, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_radius_server',
  'Update an existing RADIUS server configuration',
  {
    name: z.string().describe('RADIUS server name'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"server": "10.0.0.10", "secret": "newsecret", "auth-type": "ms_chap_v2"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateRadiusServer(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_radius_server',
  'Delete a RADIUS server configuration by name',
  {
    name: z.string().describe('RADIUS server name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteRadiusServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── TACACS+ Server Tools ──────────────────────────────────

server.tool(
  'get_tacacs_servers',
  'List all configured TACACS+ server connections',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getTacacsServers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_tacacs_server',
  'Get a specific TACACS+ server configuration by name',
  {
    name: z.string().describe('TACACS+ server name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getTacacsServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_tacacs_server',
  'Create a new TACACS+ server connection',
  {
    name: z.string().describe('TACACS+ server name'),
    server: z.string().describe('TACACS+ server hostname or IP address'),
    key: z.string().describe('TACACS+ shared secret key'),
    port: z.number().optional().default(49).describe('TACACS+ server port (default: 49)'),
    authen_type: z.enum(['auto', 'ascii', 'pap', 'chap', 'mschap']).optional().default('auto').describe('Authentication type'),
    authorization: z.enum(['enable', 'disable']).optional().default('disable').describe('Enable/disable TACACS+ authorization'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, server: tacacsServer, key, port, authen_type, authorization, vdom }) => {
    try {
      const tacacs: Record<string, unknown> = {
        name,
        server: tacacsServer,
        key,
        port,
        'authen-type': authen_type,
        authorization,
      };
      return result(await client.createTacacsServer(tacacs, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_tacacs_server',
  'Update an existing TACACS+ server configuration',
  {
    name: z.string().describe('TACACS+ server name'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"server": "10.0.0.20", "key": "newkey"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateTacacsServer(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_tacacs_server',
  'Delete a TACACS+ server configuration by name',
  {
    name: z.string().describe('TACACS+ server name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteTacacsServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── SAML Server Tools ─────────────────────────────────────

server.tool(
  'get_saml_servers',
  'List all configured SAML IdP server connections',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getSamlServers(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_saml_server',
  'Get a specific SAML IdP server configuration by name',
  {
    name: z.string().describe('SAML server name'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.getSamlServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_saml_server',
  'Create a new SAML IdP server connection',
  {
    name: z.string().describe('SAML server name'),
    entity_id: z.string().describe('SAML SP entity ID (FortiGate identifier)'),
    single_sign_on_url: z.string().describe('IdP single sign-on URL'),
    single_logout_url: z.string().optional().describe('IdP single logout URL'),
    idp_entity_id: z.string().describe('IdP entity ID'),
    idp_cert: z.string().describe('Name of installed IdP certificate for SAML verification'),
    user_name: z.string().optional().default('username').describe('SAML attribute for username'),
    group_name: z.string().optional().describe('SAML attribute for group membership'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, entity_id, single_sign_on_url, single_logout_url, idp_entity_id, idp_cert, user_name, group_name, vdom }) => {
    try {
      const saml: Record<string, unknown> = {
        name,
        'entity-id': entity_id,
        'single-sign-on-url': single_sign_on_url,
        'idp-entity-id': idp_entity_id,
        'idp-cert': idp_cert,
        'user-name': user_name,
      };
      if (single_logout_url) saml['single-logout-url'] = single_logout_url;
      if (group_name) saml['group-name'] = group_name;
      return result(await client.createSamlServer(saml, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_saml_server',
  'Update an existing SAML IdP server configuration',
  {
    name: z.string().describe('SAML server name'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"single-sign-on-url": "https://idp.example.com/sso", "idp-cert": "new-cert"})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, updates, vdom }) => {
    try {
      return result(await client.updateSamlServer(name, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_saml_server',
  'Delete a SAML IdP server configuration by name',
  {
    name: z.string().describe('SAML server name to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, vdom }) => {
    try {
      return result(await client.deleteSamlServer(name, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── FortiToken Tools ──────────────────────────────────────

server.tool(
  'get_fortitokens',
  'List all FortiToken two-factor authentication tokens',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getFortiTokens(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

// ─── FSSO Tools ────────────────────────────────────────────

server.tool(
  'get_fsso_servers',
  'List all Fortinet SSO (FSSO) agent/polling connections',
  { vdom: z.string().optional().describe('Virtual domain name (optional)') },
  async ({ vdom }) => {
    try {
      return result(await client.getFssoPolling(vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'get_fsso_server',
  'Get a specific FSSO agent/polling connection by ID',
  {
    id: z.number().describe('FSSO entry ID'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.getFssoPollingServer(id, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'create_fsso_server',
  'Create a new FSSO agent/polling connection',
  {
    name: z.string().describe('FSSO connection name'),
    server: z.string().describe('FSSO agent server hostname or IP'),
    port: z.number().optional().default(8000).describe('FSSO agent listening port (default: 8000)'),
    password: z.string().optional().describe('FSSO agent password'),
    ldap_server: z.string().optional().describe('LDAP server name for FSSO polling mode'),
    type: z.enum(['default', 'fortiems', 'fortinac', 'fortiems-cloud']).optional().default('default').describe('Server type'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ name, server: fssoServer, port, password, ldap_server, type, vdom }) => {
    try {
      const fsso: Record<string, unknown> = { name, server: fssoServer, port, type };
      if (password) fsso.password = password;
      if (ldap_server) fsso['ldap-server'] = ldap_server;
      return result(await client.createFssoPolling(fsso, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'update_fsso_server',
  'Update an existing FSSO agent/polling connection',
  {
    id: z.number().describe('FSSO entry ID'),
    updates: z.record(z.unknown()).describe('Key-value pairs to update (e.g., {"server": "10.0.0.30", "port": 8001})'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, updates, vdom }) => {
    try {
      return result(await client.updateFssoPolling(id, updates, vdom));
    } catch (e) {
      return errorResult(e);
    }
  }
);

server.tool(
  'delete_fsso_server',
  'Delete an FSSO agent/polling connection by ID',
  {
    id: z.number().describe('FSSO entry ID to delete'),
    vdom: z.string().optional().describe('Virtual domain name (optional)'),
  },
  async ({ id, vdom }) => {
    try {
      return result(await client.deleteFssoPolling(id, vdom));
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
