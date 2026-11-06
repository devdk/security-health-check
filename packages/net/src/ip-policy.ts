import { BlockList, isIP } from 'node:net';

/**
 * Addresses we must never connect to on a user's behalf: loopback, private ranges,
 * link-local (incl. cloud metadata at 169.254.169.254), CGNAT, multicast, documentation,
 * benchmarking and reserved ranges, plus IPv6 transition prefixes that can embed them.
 */
const blocked = new BlockList();

const IPV4_BLOCKS: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const IPV6_BLOCKS: Array<[string, number]> = [
  ['::', 96], // unspecified, loopback, deprecated IPv4-compatible
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48],
  ['100::', 64], // discard
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (deprecated)
  ['ff00::', 8], // multicast
];

for (const [net, prefix] of IPV4_BLOCKS) blocked.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of IPV6_BLOCKS) blocked.addSubnet(net, prefix, 'ipv6');

/** Returns the embedded IPv4 address for IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:7f00:1). */
function mappedIpv4(address: string): string | null {
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (dotted) return dotted[1]!;
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(address);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

/** True only for globally routable unicast addresses. Anything unparseable is treated as unsafe. */
export function isPublicAddress(input: string): boolean {
  const address = input.replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  const family = isIP(address);
  if (family === 4) return !blocked.check(address, 'ipv4');
  if (family === 6) {
    const v4 = mappedIpv4(address);
    if (v4) return isPublicAddress(v4);
    return !blocked.check(address, 'ipv6');
  }
  return false;
}
