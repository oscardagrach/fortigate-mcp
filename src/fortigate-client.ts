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

  // ─── Log Settings ──────────────────────────────────────────

  async getLogSettings() {
    return this.request('GET', '/api/v2/cmdb/log/setting');
  }

  async updateLogSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log/setting', settings);
  }

  async getLogEventFilter() {
    return this.request('GET', '/api/v2/cmdb/log/eventfilter');
  }

  async updateLogEventFilter(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log/eventfilter', settings);
  }

  async getLogThreatWeight() {
    return this.request('GET', '/api/v2/cmdb/log/threat-weight');
  }

  async updateLogThreatWeight(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log/threat-weight', settings);
  }

  // ─── Syslog ───────────────────────────────────────────────

  async getSyslogSettings() {
    return this.request('GET', '/api/v2/cmdb/log.syslogd/setting');
  }

  async updateSyslogSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.syslogd/setting', settings);
  }

  async getSyslogFilter() {
    return this.request('GET', '/api/v2/cmdb/log.syslogd/filter');
  }

  async updateSyslogFilter(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.syslogd/filter', settings);
  }

  // ─── FortiAnalyzer ────────────────────────────────────────

  async getFortiAnalyzerSettings() {
    return this.request('GET', '/api/v2/cmdb/log.fortianalyzer/setting');
  }

  async updateFortiAnalyzerSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.fortianalyzer/setting', settings);
  }

  async getFortiAnalyzerFilter() {
    return this.request('GET', '/api/v2/cmdb/log.fortianalyzer/filter');
  }

  async updateFortiAnalyzerFilter(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.fortianalyzer/filter', settings);
  }

  // ─── Log Disk ─────────────────────────────────────────────

  async getLogDiskSettings() {
    return this.request('GET', '/api/v2/cmdb/log.disk/setting');
  }

  async updateLogDiskSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.disk/setting', settings);
  }

  async getLogDiskFilter() {
    return this.request('GET', '/api/v2/cmdb/log.disk/filter');
  }

  async updateLogDiskFilter(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.disk/filter', settings);
  }

  // ─── FortiCloud Log ───────────────────────────────────────

  async getFortiCloudLogSettings() {
    return this.request('GET', '/api/v2/cmdb/log.fortiguard/setting');
  }

  async updateFortiCloudLogSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/log.fortiguard/setting', settings);
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

  // ─── WAF ───────────────────────────────────────────────────

  async getWafProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/waf/profile', undefined, params);
  }

  async getWafProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/waf/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── DLP ──────────────────────────────────────────────────

  async getDlpSensors(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/dlp/sensor', undefined, params);
  }

  async getDlpSensor(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/dlp/sensor/${encodeURIComponent(name)}`, undefined, params);
  }

  async getDlpFpDocSources(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/dlp/fp-doc-source', undefined, params);
  }

  // ─── Email Filter ────────────────────────────────────────

  async getEmailFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/emailfilter/profile', undefined, params);
  }

  async getEmailFilterProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/emailfilter/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── ICAP ─────────────────────────────────────────────────

  async getIcapServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/icap/server', undefined, params);
  }

  async getIcapProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/icap/profile', undefined, params);
  }

  async getIcapProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/icap/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── VoIP ─────────────────────────────────────────────────

  async getVoipProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/voip/profile', undefined, params);
  }

  async getVoipProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/voip/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── File Filter ──────────────────────────────────────────

  async getFileFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/file-filter/profile', undefined, params);
  }

  async getFileFilterProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/file-filter/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── Video Filter ────────────────────────────────────────

  async getVideoFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/videofilter/profile', undefined, params);
  }

  // ─── SCTP Filter ─────────────────────────────────────────

  async getSctpFilterProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/sctp-filter/profile', undefined, params);
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

  // ─── Access Lists ──────────────────────────────────────────

  async getAccessLists(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/access-list', undefined, params);
  }

  async getAccessList(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/router/access-list/${encodeURIComponent(name)}`, undefined, params);
  }

  async createAccessList(acl: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/access-list', acl, params);
  }

  async updateAccessList(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/access-list/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteAccessList(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/access-list/${encodeURIComponent(name)}`, undefined, params);
  }

  async getAccessLists6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/access-list6', undefined, params);
  }

  // ─── AS Path Lists ────────────────────────────────────────

  async getAspathLists(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/aspath-list', undefined, params);
  }

  async getAspathList(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/router/aspath-list/${encodeURIComponent(name)}`, undefined, params);
  }

  async createAspathList(aspath: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/aspath-list', aspath, params);
  }

  async updateAspathList(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/aspath-list/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteAspathList(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/aspath-list/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── BFD ──────────────────────────────────────────────────

  async getBfd(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/bfd', undefined, params);
  }

  async updateBfd(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/bfd', updates, params);
  }

  // ─── RIP ──────────────────────────────────────────────────

  async getRipConfig(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/rip', undefined, params);
  }

  async updateRipConfig(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/rip', updates, params);
  }

  // ─── IS-IS ────────────────────────────────────────────────

  async getIsisConfig(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/isis', undefined, params);
  }

  async updateIsisConfig(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/isis', updates, params);
  }

  // ─── Multicast / PIM ──────────────────────────────────────

  async getMulticastConfig(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/multicast', undefined, params);
  }

  async updateMulticastConfig(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/router/multicast', updates, params);
  }

  // ─── Router Policy (PBR) ──────────────────────────────────

  async getRouterPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/policy', undefined, params);
  }

  async getRouterPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/router/policy/${id}`, undefined, params);
  }

  async createRouterPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/policy', policy, params);
  }

  async updateRouterPolicy(id: number, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/policy/${id}`, updates, params);
  }

  async deleteRouterPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/policy/${id}`, undefined, params);
  }

  // ─── Key Chains ───────────────────────────────────────────

  async getKeyChains(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/key-chain', undefined, params);
  }

  async getKeyChain(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/router/key-chain/${encodeURIComponent(name)}`, undefined, params);
  }

  async createKeyChain(keychain: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/key-chain', keychain, params);
  }

  async updateKeyChain(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/key-chain/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteKeyChain(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/key-chain/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── IPv6 Static Routes ──────────────────────────────────

  async getStaticRoutes6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/static6', undefined, params);
  }

  async getStaticRoute6(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/router/static6/${id}`, undefined, params);
  }

  async createStaticRoute6(route: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/router/static6', route, params);
  }

  async updateStaticRoute6(id: number, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/router/static6/${id}`, updates, params);
  }

  async deleteStaticRoute6(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/router/static6/${id}`, undefined, params);
  }

  // ─── Prefix List 6 ───────────────────────────────────────

  async getPrefixLists6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/router/prefix-list6', undefined, params);
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

  // ─── Automation ─────────────────────────────────────────────

  async getAutomationStitches(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/automation-stitch', undefined, params);
  }

  async getAutomationStitch(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/system/automation-stitch/${encodeURIComponent(name)}`, undefined, params);
  }

  async createAutomationStitch(stitch: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/system/automation-stitch', stitch, params);
  }

  async updateAutomationStitch(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/system/automation-stitch/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteAutomationStitch(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/system/automation-stitch/${encodeURIComponent(name)}`, undefined, params);
  }

  async getAutomationTriggers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/automation-trigger', undefined, params);
  }

  async getAutomationActions(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/automation-action', undefined, params);
  }

  // ─── Virtual Wire Pair ────────────────────────────────────

  async getVirtualWirePairs(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/virtual-wire-pair', undefined, params);
  }

  async createVirtualWirePair(pair: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/system/virtual-wire-pair', pair, params);
  }

  async deleteVirtualWirePair(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/system/virtual-wire-pair/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── VDOM Link ────────────────────────────────────────────

  async getVdomLinks() {
    return this.request('GET', '/api/v2/cmdb/system/vdom-link');
  }

  async createVdomLink(link: Record<string, unknown>) {
    return this.request('POST', '/api/v2/cmdb/system/vdom-link', link);
  }

  async deleteVdomLink(name: string) {
    return this.request('DELETE', `/api/v2/cmdb/system/vdom-link/${encodeURIComponent(name)}`);
  }

  // ─── Session Helper ───────────────────────────────────────

  async getSessionHelpers() {
    return this.request('GET', '/api/v2/cmdb/system/session-helper');
  }

  async updateSessionHelper(id: number, updates: Record<string, unknown>) {
    return this.request('PUT', `/api/v2/cmdb/system/session-helper/${id}`, updates);
  }

  // ─── NetFlow ──────────────────────────────────────────────

  async getNetflowSettings() {
    return this.request('GET', '/api/v2/cmdb/system/netflow');
  }

  async updateNetflowSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/netflow', settings);
  }

  // ─── sFlow ────────────────────────────────────────────────

  async getSflowSettings() {
    return this.request('GET', '/api/v2/cmdb/system/sflow');
  }

  async updateSflowSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/sflow', settings);
  }

  // ─── FortiGuard ───────────────────────────────────────────

  async getFortiGuardSettings() {
    return this.request('GET', '/api/v2/cmdb/system/fortiguard');
  }

  async updateFortiGuardSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/fortiguard', settings);
  }

  // ─── Security Fabric (CSF) ────────────────────────────────

  async getCsfSettings() {
    return this.request('GET', '/api/v2/cmdb/system/csf');
  }

  async updateCsfSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/csf', settings);
  }

  // ─── Central Management ───────────────────────────────────

  async getCentralManagement() {
    return this.request('GET', '/api/v2/cmdb/system/central-management');
  }

  async updateCentralManagement(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/system/central-management', settings);
  }

  // ─── Link Monitor ────────────────────────────────────────

  async getLinkMonitors(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/link-monitor', undefined, params);
  }

  async getLinkMonitor(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/system/link-monitor/${encodeURIComponent(name)}`, undefined, params);
  }

  async createLinkMonitor(monitor: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/system/link-monitor', monitor, params);
  }

  async updateLinkMonitor(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/system/link-monitor/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteLinkMonitor(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/system/link-monitor/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── Object Tagging ──────────────────────────────────────

  async getObjectTags(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/object-tagging', undefined, params);
  }

  async createObjectTag(tag: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/system/object-tagging', tag, params);
  }

  async deleteObjectTag(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/system/object-tagging/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── Replacement Messages ─────────────────────────────────

  async getReplacemsgGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/system/replacemsg-group', undefined, params);
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

  // ─── SSL VPN Portal ────────────────────────────────────────

  async getSslVpnPortals(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/vpn.ssl.web/portal', undefined, params);
  }

  async getSslVpnPortal(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/vpn.ssl.web/portal/${encodeURIComponent(name)}`, undefined, params);
  }

  async createSslVpnPortal(portal: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/vpn.ssl.web/portal', portal, params);
  }

  async updateSslVpnPortal(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/vpn.ssl.web/portal/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteSslVpnPortal(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/vpn.ssl.web/portal/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── SSL VPN Realm ────────────────────────────────────────

  async getSslVpnRealms(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/vpn.ssl.web/realm', undefined, params);
  }

  async getSslVpnRealm(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/vpn.ssl.web/realm/${encodeURIComponent(name)}`, undefined, params);
  }

  async createSslVpnRealm(realm: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/vpn.ssl.web/realm', realm, params);
  }

  async updateSslVpnRealm(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/vpn.ssl.web/realm/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteSslVpnRealm(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/vpn.ssl.web/realm/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── PPTP ─────────────────────────────────────────────────

  async getPptpSettings() {
    return this.request('GET', '/api/v2/cmdb/vpn.pptp/pptp');
  }

  async updatePptpSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/vpn.pptp/pptp', settings);
  }

  // ─── L2TP ─────────────────────────────────────────────────

  async getL2tpSettings() {
    return this.request('GET', '/api/v2/cmdb/vpn.l2tp/l2tp');
  }

  async updateL2tpSettings(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/vpn.l2tp/l2tp', settings);
  }

  // ─── VPN Certificate ─────────────────────────────────────

  async getVpnCertificateCAs() {
    return this.request('GET', '/api/v2/cmdb/vpn.certificate/ca');
  }

  async getVpnCertificateRemote() {
    return this.request('GET', '/api/v2/cmdb/vpn.certificate/remote');
  }

  async getVpnCertificateCRL() {
    return this.request('GET', '/api/v2/cmdb/vpn.certificate/crl');
  }

  // ─── IPv6 Firewall Policies ─────────────────────────────────

  async getFirewallPolicies6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/policy6', undefined, params);
  }

  async getFirewallPolicy6(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/policy6/${id}`, undefined, params);
  }

  async createFirewallPolicy6(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/policy6', policy, params);
  }

  async updateFirewallPolicy6(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/policy6/${id}`, policy, params);
  }

  async deleteFirewallPolicy6(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/policy6/${id}`, undefined, params);
  }

  // ─── Central SNAT ──────────────────────────────────────────

  async getCentralSnatMap(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/central-snat-map', undefined, params);
  }

  async getCentralSnatEntry(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/central-snat-map/${id}`, undefined, params);
  }

  async createCentralSnatEntry(entry: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/central-snat-map', entry, params);
  }

  async updateCentralSnatEntry(id: number, entry: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/central-snat-map/${id}`, entry, params);
  }

  async deleteCentralSnatEntry(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/central-snat-map/${id}`, undefined, params);
  }

  // ─── DoS Policies ─────────────────────────────────────────

  async getDosPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/DoS-policy', undefined, params);
  }

  async getDosPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/DoS-policy/${id}`, undefined, params);
  }

  async createDosPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/DoS-policy', policy, params);
  }

  async updateDosPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/DoS-policy/${id}`, policy, params);
  }

  async deleteDosPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/DoS-policy/${id}`, undefined, params);
  }

  // ─── Multicast Policies ───────────────────────────────────

  async getMulticastPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/multicast-policy', undefined, params);
  }

  async getMulticastPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/multicast-policy/${id}`, undefined, params);
  }

  async createMulticastPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/multicast-policy', policy, params);
  }

  async updateMulticastPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/multicast-policy/${id}`, policy, params);
  }

  async deleteMulticastPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/multicast-policy/${id}`, undefined, params);
  }

  // ─── Proxy Policies ───────────────────────────────────────

  async getProxyPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/proxy-policy', undefined, params);
  }

  async getProxyPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/proxy-policy/${id}`, undefined, params);
  }

  async createProxyPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/proxy-policy', policy, params);
  }

  async updateProxyPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/proxy-policy/${id}`, policy, params);
  }

  async deleteProxyPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/proxy-policy/${id}`, undefined, params);
  }

  // ─── Local-in Policies ────────────────────────────────────

  async getLocalInPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/local-in-policy', undefined, params);
  }

  async getLocalInPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/local-in-policy/${id}`, undefined, params);
  }

  async createLocalInPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/local-in-policy', policy, params);
  }

  async updateLocalInPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/local-in-policy/${id}`, policy, params);
  }

  async deleteLocalInPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/local-in-policy/${id}`, undefined, params);
  }

  // ─── IPv6 Address Objects ─────────────────────────────────

  async getAddresses6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/address6', undefined, params);
  }

  async getAddress6(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/address6/${encodeURIComponent(name)}`, undefined, params);
  }

  async createAddress6(address: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/address6', address, params);
  }

  async updateAddress6(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/address6/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteAddress6(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/address6/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── IPv6 Address Groups ──────────────────────────────────

  async getAddressGroups6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/addrgrp6', undefined, params);
  }

  // ─── Multicast Addresses ──────────────────────────────────

  async getMulticastAddresses(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/multicast-address', undefined, params);
  }

  // ─── Internet Service ─────────────────────────────────────

  async getInternetServices(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/internet-service-name', undefined, params);
  }

  // ─── Service Categories ───────────────────────────────────

  async getServiceCategories(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall.service/category', undefined, params);
  }

  // ─── VIP Groups ───────────────────────────────────────────

  async getVipGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/vipgrp', undefined, params);
  }

  // ─── IPv6 IP Pools ────────────────────────────────────────

  async getIpPools6(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/ippool6', undefined, params);
  }

  // ─── Shaping Profiles ─────────────────────────────────────

  async getShapingProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/shaping-profile', undefined, params);
  }

  // ─── Shaping Policies ─────────────────────────────────────

  async getShapingPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/firewall/shaping-policy', undefined, params);
  }

  async getShapingPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/firewall/shaping-policy/${id}`, undefined, params);
  }

  async createShapingPolicy(policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/firewall/shaping-policy', policy, params);
  }

  async updateShapingPolicy(id: number, policy: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/firewall/shaping-policy/${id}`, policy, params);
  }

  async deleteShapingPolicy(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/firewall/shaping-policy/${id}`, undefined, params);
  }

  // ─── Wireless Controller ───────────────────────────────────

  async getManagedAPs(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wireless-controller/wtp', undefined, params);
  }

  async getManagedAP(id: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wireless-controller/wtp/${encodeURIComponent(id)}`, undefined, params);
  }

  async updateManagedAP(id: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wireless-controller/wtp/${encodeURIComponent(id)}`, updates, params);
  }

  async deleteManagedAP(id: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wireless-controller/wtp/${encodeURIComponent(id)}`, undefined, params);
  }

  async getWtpProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wireless-controller/wtp-profile', undefined, params);
  }

  async getWtpProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wireless-controller/wtp-profile/${encodeURIComponent(name)}`, undefined, params);
  }

  async getWirelessVaps(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wireless-controller/vap', undefined, params);
  }

  async getWirelessVap(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wireless-controller/vap/${encodeURIComponent(name)}`, undefined, params);
  }

  async createWirelessVap(vap: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/wireless-controller/vap', vap, params);
  }

  async updateWirelessVap(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wireless-controller/vap/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteWirelessVap(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wireless-controller/vap/${encodeURIComponent(name)}`, undefined, params);
  }

  async getWidsProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wireless-controller/wids-profile', undefined, params);
  }

  async getWidsProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wireless-controller/wids-profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── Switch Controller ─────────────────────────────────────

  async getManagedSwitches(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller/managed-switch', undefined, params);
  }

  async getManagedSwitch(id: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/switch-controller/managed-switch/${encodeURIComponent(id)}`, undefined, params);
  }

  async updateManagedSwitch(id: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/switch-controller/managed-switch/${encodeURIComponent(id)}`, updates, params);
  }

  async deleteManagedSwitch(id: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/switch-controller/managed-switch/${encodeURIComponent(id)}`, undefined, params);
  }

  async getSwitchVlans(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller/vlan', undefined, params);
  }

  async createSwitchVlan(vlan: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/switch-controller/vlan', vlan, params);
  }

  async deleteSwitchVlan(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/switch-controller/vlan/${encodeURIComponent(name)}`, undefined, params);
  }

  async getSwitchStpSettings(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller/stp-settings', undefined, params);
  }

  async updateSwitchStpSettings(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/switch-controller/stp-settings', updates, params);
  }

  async getSwitchQosPolicies(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller.qos/qos-policy', undefined, params);
  }

  async getSwitchQosDot1pMap(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller.qos/dot1p-map', undefined, params);
  }

  async getSwitchQosIpDscpMap(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/switch-controller.qos/ip-dscp-map', undefined, params);
  }

  // ─── Web Proxy ─────────────────────────────────────────────

  async getWebProxyGlobal() {
    return this.request('GET', '/api/v2/cmdb/web-proxy/global');
  }

  async updateWebProxyGlobal(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/web-proxy/global', settings);
  }

  async getWebProxyExplicit() {
    return this.request('GET', '/api/v2/cmdb/web-proxy/explicit');
  }

  async updateWebProxyExplicit(settings: Record<string, unknown>) {
    return this.request('PUT', '/api/v2/cmdb/web-proxy/explicit', settings);
  }

  async getWebProxyForwardServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/web-proxy/forward-server', undefined, params);
  }

  async getWebProxyForwardServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/web-proxy/forward-server/${encodeURIComponent(name)}`, undefined, params);
  }

  async createWebProxyForwardServer(server: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/web-proxy/forward-server', server, params);
  }

  async updateWebProxyForwardServer(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/web-proxy/forward-server/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteWebProxyForwardServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/web-proxy/forward-server/${encodeURIComponent(name)}`, undefined, params);
  }

  async getWebProxyUrlMatches(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/web-proxy/url-match', undefined, params);
  }

  async createWebProxyUrlMatch(match: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/web-proxy/url-match', match, params);
  }

  async deleteWebProxyUrlMatch(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/web-proxy/url-match/${encodeURIComponent(name)}`, undefined, params);
  }

  // ─── LDAP Servers ──────────────────────────────────────────

  async getLdapServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/ldap', undefined, params);
  }

  async getLdapServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/user/ldap/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createLdapServer(ldap: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/user/ldap', ldap, params);
  }

  async updateLdapServer(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/user/ldap/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteLdapServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/user/ldap/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── RADIUS Servers ────────────────────────────────────────

  async getRadiusServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/radius', undefined, params);
  }

  async getRadiusServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/user/radius/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createRadiusServer(radius: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/user/radius', radius, params);
  }

  async updateRadiusServer(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/user/radius/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteRadiusServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/user/radius/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── TACACS+ Servers ───────────────────────────────────────

  async getTacacsServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/tacacs+', undefined, params);
  }

  async getTacacsServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/user/tacacs+/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createTacacsServer(tacacs: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/user/tacacs+', tacacs, params);
  }

  async updateTacacsServer(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/user/tacacs+/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteTacacsServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/user/tacacs+/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── SAML ──────────────────────────────────────────────────

  async getSamlServers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/saml', undefined, params);
  }

  async getSamlServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/user/saml/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  async createSamlServer(saml: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/user/saml', saml, params);
  }

  async updateSamlServer(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'PUT',
      `/api/v2/cmdb/user/saml/${encodeURIComponent(name)}`,
      updates,
      params
    );
  }

  async deleteSamlServer(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'DELETE',
      `/api/v2/cmdb/user/saml/${encodeURIComponent(name)}`,
      undefined,
      params
    );
  }

  // ─── FortiToken ────────────────────────────────────────────

  async getFortiTokens(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/fortitoken', undefined, params);
  }

  // ─── FSSO ──────────────────────────────────────────────────

  async getFssoPolling(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/user/fsso', undefined, params);
  }

  async getFssoPollingServer(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request(
      'GET',
      `/api/v2/cmdb/user/fsso/${id}`,
      undefined,
      params
    );
  }

  async createFssoPolling(fsso: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/user/fsso', fsso, params);
  }

  async updateFssoPolling(id: number, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/user/fsso/${id}`, updates, params);
  }

  async deleteFssoPolling(id: number, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/user/fsso/${id}`, undefined, params);
  }

  // ─── WAN Optimization ──────────────────────────────────────

  // Profiles
  async getWanoptProfiles(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/profile', undefined, params);
  }

  async getWanoptProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wanopt/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  async createWanoptProfile(profile: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/wanopt/profile', profile, params);
  }

  async updateWanoptProfile(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wanopt/profile/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteWanoptProfile(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wanopt/profile/${encodeURIComponent(name)}`, undefined, params);
  }

  // Peers
  async getWanoptPeers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/peer', undefined, params);
  }

  async getWanoptPeer(peerHostId: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wanopt/peer/${encodeURIComponent(peerHostId)}`, undefined, params);
  }

  async createWanoptPeer(peer: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/wanopt/peer', peer, params);
  }

  async updateWanoptPeer(peerHostId: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wanopt/peer/${encodeURIComponent(peerHostId)}`, updates, params);
  }

  async deleteWanoptPeer(peerHostId: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wanopt/peer/${encodeURIComponent(peerHostId)}`, undefined, params);
  }

  // Auth Groups
  async getWanoptAuthGroups(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/auth-group', undefined, params);
  }

  async getWanoptAuthGroup(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wanopt/auth-group/${encodeURIComponent(name)}`, undefined, params);
  }

  async createWanoptAuthGroup(authGroup: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/wanopt/auth-group', authGroup, params);
  }

  async updateWanoptAuthGroup(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wanopt/auth-group/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteWanoptAuthGroup(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wanopt/auth-group/${encodeURIComponent(name)}`, undefined, params);
  }

  // CDN Rules
  async getWanoptCdnRules(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/content-delivery-network-rule', undefined, params);
  }

  async getWanoptCdnRule(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', `/api/v2/cmdb/wanopt/content-delivery-network-rule/${encodeURIComponent(name)}`, undefined, params);
  }

  async createWanoptCdnRule(rule: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('POST', '/api/v2/cmdb/wanopt/content-delivery-network-rule', rule, params);
  }

  async updateWanoptCdnRule(name: string, updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', `/api/v2/cmdb/wanopt/content-delivery-network-rule/${encodeURIComponent(name)}`, updates, params);
  }

  async deleteWanoptCdnRule(name: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('DELETE', `/api/v2/cmdb/wanopt/content-delivery-network-rule/${encodeURIComponent(name)}`, undefined, params);
  }

  // Cache Service (singleton)
  async getWanoptCacheService(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/cache-service', undefined, params);
  }

  async updateWanoptCacheService(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/wanopt/cache-service', updates, params);
  }

  // Web Cache (singleton)
  async getWanoptWebcache(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/webcache', undefined, params);
  }

  async updateWanoptWebcache(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/wanopt/webcache', updates, params);
  }

  // Remote Storage (singleton)
  async getWanoptRemoteStorage(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/remote-storage', undefined, params);
  }

  async updateWanoptRemoteStorage(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/wanopt/remote-storage', updates, params);
  }

  // Settings (singleton)
  async getWanoptSettings(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/cmdb/wanopt/settings', undefined, params);
  }

  async updateWanoptSettings(updates: Record<string, unknown>, vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('PUT', '/api/v2/cmdb/wanopt/settings', updates, params);
  }

  // ─── Monitor: FortiSwitch ──────────────────────────────────

  async getMonitorSwitchPorts(serial?: string, vdom?: string) {
    const params: Record<string, string> = {};
    if (serial) params['mkey'] = serial;
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/switch-controller/managed-switch/port-stats', undefined, params);
  }

  async getMonitorSwitchStatus(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/switch-controller/managed-switch/status', undefined, params);
  }

  async getMonitorSwitchHealth(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/switch-controller/managed-switch/health', undefined, params);
  }

  async getMonitorSwitchFaceplate(serial: string, vdom?: string) {
    const params: Record<string, string> = { mkey: serial };
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/switch-controller/managed-switch/faceplate', undefined, params);
  }

  async getMonitorSwitchTransceivers(vdom?: string) {
    const params: Record<string, string> = {};
    if (vdom) params['vdom'] = vdom;
    return this.request('GET', '/api/v2/monitor/switch-controller/managed-switch/transceivers', undefined, params);
  }
}
