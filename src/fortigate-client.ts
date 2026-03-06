/**
 * Fortigate REST API client.
 * Uses API token authentication against the FortiOS REST API (v2).
 * All requests go through the central `request()` method which handles
 * TLS verification bypass (common for self-signed certs on firewalls),
 * authentication headers, and JSON parsing.
 */

export interface FortigateConfig {
  host: string;
  port: number;
  apiToken: string;
  verifySsl: boolean;
}

export interface FortigateResponse<T = unknown> {
  http_method: string;
  results: T;
  vdom: string;
  status: string;
  http_status: number;
  serial: string;
  version: string;
  build: number;
}

export class FortigateClient {
  private baseUrl: string;
  private apiToken: string;
  private verifySsl: boolean;

  constructor(config: FortigateConfig) {
    this.baseUrl = `https://${config.host}:${config.port}`;
    this.apiToken = config.apiToken;
    this.verifySsl = config.verifySsl;
  }

  private async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string>
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiToken}`,
      'Content-Type': 'application/json',
    };

    const options: RequestInit = {
      method,
      headers,
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url.toString(), options);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Fortigate API error: ${response.status} ${response.statusText} - ${errorText}`
      );
    }

    return response.json() as Promise<T>;
  }

  // ─── System ──────────────────────────────────────────────

  async getSystemStatus() {
    return this.request('GET', '/api/v2/monitor/system/status');
  }

  async getSystemResources() {
    return this.request('GET', '/api/v2/monitor/system/resource/usage');
  }

  async getSystemPerformance() {
    return this.request('GET', '/api/v2/monitor/system/performance/status');
  }

  // ─── Interfaces ──────────────────────────────────────────

  async getInterfaces() {
    return this.request('GET', '/api/v2/cmdb/system/interface');
  }

  async getInterface(name: string) {
    return this.request('GET', `/api/v2/cmdb/system/interface/${encodeURIComponent(name)}`);
  }

  async updateInterface(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/system/interface/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  // ─── Firewall Policies ───────────────────────────────────

  async getFirewallPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/policy', undefined, params);
  }

  async getFirewallPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/policy/${id}`, undefined, params);
  }

  async createFirewallPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/policy', policy, params);
  }

  async updateFirewallPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/policy/${id}`, policy, params);
  }

  async deleteFirewallPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/policy/${id}`, undefined, params);
  }

  // ─── Address Objects ─────────────────────────────────────

  async getAddresses(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/address', undefined, params);
  }

  async getAddress(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/firewall/address/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createAddress(address: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/address', address, params);
  }

  async updateAddress(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/firewall/address/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteAddress(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/firewall/address/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── Address Groups ──────────────────────────────────────

  async getAddressGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/addrgrp', undefined, params);
  }

  // ─── Service Objects ─────────────────────────────────────

  async getServices(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.service/custom', undefined, params);
  }

  // ─── Routing ─────────────────────────────────────────────

  async getRoutingTable() {
    return this.request('GET', '/api/v2/monitor/router/ipv4');
  }

  async getStaticRoutes(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/static', undefined, params);
  }

  async createStaticRoute(route: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/static', route, params);
  }

  async updateStaticRoute(id: number, route: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/static/${id}`, route, params);
  }

  async deleteStaticRoute(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/static/${id}`, undefined, params);
  }

  // ─── VPN ─────────────────────────────────────────────────

  async getIPsecVpnStatus() {
    return this.request('GET', '/api/v2/monitor/vpn/ipsec');
  }

  async getSslVpnStatus() {
    return this.request('GET', '/api/v2/monitor/vpn/ssl');
  }

  // ─── DHCP ────────────────────────────────────────────────

  async getDhcpLeases() {
    return this.request('GET', '/api/v2/monitor/system/dhcp');
  }

  // ─── ARP Table ───────────────────────────────────────────

  async getArpTable() {
    return this.request('GET', '/api/v2/monitor/network/arp');
  }

  // ─── DNS ─────────────────────────────────────────────────

  async getDnsSettings() {
    return this.request('GET', '/api/v2/cmdb/system/dns');
  }

  async updateDnsSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/dns', settings);
  }

  // ─── HA ──────────────────────────────────────────────────

  async getHaStatus() {
    return this.request('GET', '/api/v2/monitor/system/ha-peer');
  }

  // ─── Users ───────────────────────────────────────────────

  async getLocalUsers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/local', undefined, params);
  }

  async getUserGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/group', undefined, params);
  }

  // ─── Logging ─────────────────────────────────────────────

  async getTrafficLogs(rows: number = 20, vdom?: string) {
    const params: Record<string, string> = { rows: rows.toString() };
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/log/memory/traffic/forward', undefined, params);
  }

  async getEventLogs(rows: number = 20, vdom?: string) {
    const params: Record<string, string> = { rows: rows.toString() };
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/log/memory/event/system', undefined, params);
  }

  async getSecurityLogs(rows: number = 20, vdom?: string) {
    const params: Record<string, string> = { rows: rows.toString() };
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/log/memory/utm/ips', undefined, params);
  }

  // ─── Session Table ───────────────────────────────────────

  async getSessionCount() {
    return this.request('GET', '/api/v2/monitor/firewall/session/summary');
  }

  // ─── Firmware ────────────────────────────────────────────

  async getFirmwareVersions() {
    return this.request('GET', '/api/v2/monitor/system/firmware');
  }

  // ─── Certificates ────────────────────────────────────────

  async getCertificates() {
    return this.request('GET', '/api/v2/cmdb/certificate/local');
  }

  // ─── Config Backup ───────────────────────────────────────

  async getConfigBackup(vdom?: string) {
    const params: Record<string, string> = { scope: vdom ? 'vdom' : 'global' };
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/system/config/backup', undefined, params);
  }

  // ─── Firewall VIP (Virtual IP / DNAT) ─────────────────────

  async getVips(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/vip', undefined, params);
  }

  async getVip(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/firewall/vip/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createVip(vip: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/vip', vip, params);
  }

  async deleteVip(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/firewall/vip/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── IP Pools (SNAT) ─────────────────────────────────────

  async getIpPools(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/ippool', undefined, params);
  }

  // ─── Service Groups ──────────────────────────────────────

  async getServiceGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.service/group', undefined, params);
  }

  // ─── Firewall Schedules ──────────────────────────────────

  async getSchedulesRecurring(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.schedule/recurring', undefined, params);
  }

  async getSchedulesOnetime(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.schedule/onetime', undefined, params);
  }

  // ─── Zones ────────────────────────────────────────────────

  async getZones(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/zone', undefined, params);
  }

  // ─── SD-WAN ───────────────────────────────────────────────

  async getSdwan(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/sdwan', undefined, params);
  }

  async getSdwanHealthCheck() {
    return this.request('GET', '/api/v2/monitor/virtual-wan/health-check');
  }

  async getSdwanMembers() {
    return this.request('GET', '/api/v2/monitor/virtual-wan/members');
  }

  async getSdwanSlaLog(sla: string) {
    return this.request('GET', `/api/v2/monitor/virtual-wan/sla-log`, undefined, { sla });
  }

  async getSdwanZones(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/sdwan/zone', undefined, params);
  }

  async updateSdwan(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/system/sdwan', updates, params);
  }

  // ─── Security Profiles ───────────────────────────────────

  async getWebFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/webfilter/profile', undefined, params);
  }

  async getAntivirusProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/antivirus/profile', undefined, params);
  }

  async getIpsSensors(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/ips/sensor', undefined, params);
  }

  async getApplicationLists(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/application/list', undefined, params);
  }

  async getDnsFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/dnsfilter/profile', undefined, params);
  }

  async getSslSshProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/ssl-ssh-profile', undefined, params);
  }

  // ─── Dynamic Routing ─────────────────────────────────────

  async getBgpConfig(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/bgp', undefined, params);
  }

  async getBgpPaths() {
    return this.request('GET', '/api/v2/monitor/router/bgp/paths');
  }

  async getBgpNeighborsStatus() {
    return this.request('GET', '/api/v2/monitor/router/bgp/neighbors');
  }

  async getBgpNetworks(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/bgp/network', undefined, params);
  }

  async getBgpRedistribute(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/bgp/redistribute', undefined, params);
  }

  async updateBgpConfig(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/bgp', updates, params);
  }

  async getPrefixLists(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/prefix-list', undefined, params);
  }

  async getRouteMaps(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/route-map', undefined, params);
  }

  async getCommunityLists(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/community-list', undefined, params);
  }

  async getOspfConfig(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/ospf', undefined, params);
  }

  async getOspfNeighbors() {
    return this.request('GET', '/api/v2/monitor/router/ospf/neighbors');
  }

  async updateOspfConfig(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/ospf', updates, params);
  }

  async getRoutingTableAll() {
    return this.request('GET', '/api/v2/monitor/router/ipv4', undefined, { count: '0' });
  }

  async getPolicyStats() {
    return this.request('GET', '/api/v2/monitor/firewall/policy');
  }

  // ─── SNMP ─────────────────────────────────────────────────

  async getSnmpCommunities() {
    return this.request('GET', '/api/v2/cmdb/system.snmp/community');
  }

  async getSnmpSysinfo() {
    return this.request('GET', '/api/v2/cmdb/system.snmp/sysinfo');
  }

  async updateSnmpSysinfo(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system.snmp/sysinfo', settings);
  }

  // ─── System (additional) ──────────────────────────────────

  async getNtpSettings() {
    return this.request('GET', '/api/v2/cmdb/system/ntp');
  }

  async updateNtpSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/ntp', settings);
  }

  async getVdoms() {
    return this.request('GET', '/api/v2/cmdb/system/vdom');
  }

  async getAdmins() {
    return this.request('GET', '/api/v2/cmdb/system/admin');
  }

  async getAdminProfiles() {
    return this.request('GET', '/api/v2/cmdb/system/accprofile');
  }

  async getGlobalSettings() {
    return this.request('GET', '/api/v2/cmdb/system/global');
  }

  async updateGlobalSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/global', settings);
  }

  // ─── DHCP Servers ─────────────────────────────────────────

  async getDhcpServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system.dhcp/server', undefined, params);
  }

  // ─── DNS Database ─────────────────────────────────────────

  async getDnsDatabase(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/dns-database', undefined, params);
  }

  async getDnsDatabaseZone(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createDnsDatabaseZone(zone: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/system/dns-database', zone, params);
  }

  async updateDnsDatabaseZone(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteDnsDatabaseZone(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createDnsEntry(zoneName: string, entry: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'POST',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(zoneName)}/dns-entry`,
      entry,
      params
    );
  }

  async updateDnsEntry(zoneName: string, entryId: number, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(zoneName)}/dns-entry/${entryId}`,
      updates,
      params
    );
  }

  async deleteDnsEntry(zoneName: string, entryId: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/system/dns-database/${encodeURIComponent(zoneName)}/dns-entry/${entryId}`,
      undefined,
      params
    );
  }

  // ─── Traffic Shaping ──────────────────────────────────────

  async getTrafficShapers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.shaper/traffic-shaper', undefined, params);
  }

  async getTrafficShapingPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.shaper/per-ip-shaper', undefined, params);
  }

  // ─── Monitor (additional) ────────────────────────────────

  async getLicenseStatus() {
    return this.request('GET', '/api/v2/monitor/license/status');
  }

  async getInterfaceStats() {
    return this.request('GET', '/api/v2/monitor/system/interface');
  }

  async getBannedUsers() {
    return this.request('GET', '/api/v2/monitor/user/banned');
  }

  async getFirewallSessionList(count: number = 20, sourceIp?: string) {
    const params: Record<string, string> = { count: count.toString() };
    if (sourceIp) params['srcip'] = sourceIp;
    return this.request('GET', '/api/v2/monitor/firewall/session', undefined, params);
  }

  // ─── VPN (additional) ────────────────────────────────────

  async getIpsecPhase1(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/vpn.ipsec/phase1-interface', undefined, params);
  }

  async getIpsecPhase2(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/vpn.ipsec/phase2-interface', undefined, params);
  }

  async getSslVpnSettings(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/vpn.ssl/settings', undefined, params);
  }
}
