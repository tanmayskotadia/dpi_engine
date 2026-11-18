const net = require('node:net');
const { domainToASCII } = require('node:url');

const RULE_KEYS = Object.freeze({
    ip: 'blockedIPs',
    app: 'blockedApps',
    domain: 'blockedDomains',
    port: 'blockedPorts',
    protocol: 'blockedProtocols',
});
const APPLICATIONS = Object.freeze([
    'Unknown', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC', 'Google', 'Facebook',
    'YouTube', 'Twitter/X', 'Instagram', 'Netflix', 'Amazon', 'Microsoft',
    'Apple', 'WhatsApp', 'Telegram', 'TikTok', 'Spotify', 'Zoom', 'Discord',
    'GitHub', 'Cloudflare',
]);
const PROTOCOLS = Object.freeze(['tcp', 'udp', 'icmp', 'icmpv6', 'arp']);

class RuleValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'RuleValidationError';
        this.status = 400;
    }
}

function invalid(message) { throw new RuleValidationError(message); }
function textValue(value) {
    if (typeof value !== 'string' || !value.trim()) invalid('A non-empty rule value is required.');
    if (value.length > 512) invalid('The rule value is too long.');
    return value.trim();
}

function ipv6Bytes(address) {
    let text = address;
    if (text.includes('.')) {
        const separator = text.lastIndexOf(':');
        const octets = text.slice(separator + 1).split('.').map(Number);
        text = text.slice(0, separator + 1) + ((octets[0] << 8) | octets[1]).toString(16) + ':' + ((octets[2] << 8) | octets[3]).toString(16);
    }
    const halves = text.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const words = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
    return words.flatMap(word => [parseInt(word, 16) >> 8, parseInt(word, 16) & 255]);
}

function formatIPv6(bytes) {
    const words = Array.from({ length: 8 }, (_, index) => ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16));
    let longestStart = -1;
    let longestLength = 1;
    for (let index = 0; index < words.length;) {
        if (words[index] !== '0') { index++; continue; }
        const start = index;
        while (index < words.length && words[index] === '0') index++;
        if (index - start > longestLength) {
            longestStart = start;
            longestLength = index - start;
        }
    }
    if (longestStart < 0) return words.join(':');
    return words.slice(0, longestStart).join(':') + '::' + words.slice(longestStart + longestLength).join(':');
}

function normalizeIP(value) {
    const parts = textValue(value).split('/');
    if (parts.length > 2) invalid('Use an IPv4 or IPv6 address, optionally followed by a CIDR prefix.');
    const address = parts[0];
    const version = net.isIP(address);
    // Interface scopes are machine-specific and cannot identify packet addresses.
    if (!version || address.includes('%')) invalid('Enter a valid IPv4 or IPv6 address, such as 192.168.1.50 or 2001:db8::1.');
    const bits = version === 4 ? 32 : 128;
    if (parts.length === 2 && (!/^\d{1,3}$/.test(parts[1]) || Number(parts[1]) > bits)) {
        invalid(`CIDR prefix must be a whole number between 0 and ${bits} for this address.`);
    }
    const prefix = parts.length === 2 ? Number(parts[1]) : bits;
    const bytes = version === 4 ? address.split('.').map(Number) : ipv6Bytes(address);
    for (let index = 0; index < bytes.length; index++) {
        const keep = Math.min(8, Math.max(0, prefix - index * 8));
        bytes[index] &= keep ? (255 << (8 - keep)) & 255 : 0;
    }
    const normalized = version === 4 ? bytes.join('.') : formatIPv6(bytes);
    return prefix === bits ? normalized : `${normalized}/${prefix}`;
}

function normalizeDomain(value) {
    let domain = textValue(value).toLowerCase();
    const wildcard = domain.startsWith('*.');
    if (wildcard) domain = domain.slice(2);
    if (domain.endsWith('.')) domain = domain.slice(0, -1);
    if (!domain || /[\s/:@?#%*\\]/.test(domain)) invalid('Use a domain name such as example.com or *.example.com, without a URL, port, or path.');
    domain = domainToASCII(domain).toLowerCase();
    if (!domain || domain.length > 253 || net.isIP(domain) || !domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
        invalid('Enter a valid domain name. Use an IP rule for an IP address.');
    }
    return (wildcard ? '*.' : '') + domain;
}

function normalizeApp(value) {
    const name = textValue(value).toLowerCase();
    const canonical = APPLICATIONS.find(app => app.toLowerCase() === name);
    if (canonical) return canonical;
    if (name === 'twitter') return 'Twitter/X'; // Preserve legacy saved rules.
    invalid('Choose a supported application or application protocol.');
}

function normalizePort(value) {
    const match = textValue(value).toLowerCase().match(/^(?:(tcp|udp):)?(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!match) invalid('Use a port or range, optionally prefixed with tcp: or udp:, such as 443 or tcp:8000-8080.');
    const first = Number(match[2]);
    const last = match[3] ? Number(match[3]) : first;
    if (first < 1 || last > 65535 || first > last) invalid('Ports must be between 1 and 65535, with the range start no greater than its end.');
    return (match[1] ? match[1] + ':' : '') + first + (last === first ? '' : '-' + last);
}

function normalizeProtocol(value) {
    const protocol = textValue(value).toLowerCase();
    if (!PROTOCOLS.includes(protocol)) invalid('Choose TCP, UDP, ICMP, ICMPv6, or ARP.');
    return protocol;
}

const normalizers = { ip: normalizeIP, app: normalizeApp, domain: normalizeDomain, port: normalizePort, protocol: normalizeProtocol };
function normalizeRule(type, value) {
    if (!Object.hasOwn(normalizers, type)) invalid('Unknown rule type. Use ip, app, domain, port, or protocol.');
    return normalizers[type](value);
}

function emptyRules() {
    return Object.fromEntries(Object.values(RULE_KEYS).map(key => [key, []]));
}

function normalizeRules(saved) {
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) invalid('Saved rules must be an object.');
    const rules = emptyRules();
    for (const [type, key] of Object.entries(RULE_KEYS)) {
        if (saved[key] === undefined) continue;
        if (!Array.isArray(saved[key])) invalid(`Saved ${key} must be an array.`);
        rules[key] = [...new Set(saved[key].map(value => normalizeRule(type, value)))];
    }
    return rules;
}

module.exports = { APPLICATIONS, PROTOCOLS, RULE_KEYS, RuleValidationError, emptyRules, normalizeRule, normalizeRules };
