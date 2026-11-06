import { describe, expect, it } from 'vitest';
import { isPublicAddress } from '../src/ip-policy';

describe('isPublicAddress', () => {
  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254', // cloud metadata
    '100.64.0.1', // CGNAT
    '0.0.0.0',
    '192.0.2.10',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:a9fe:a9fe', // mapped 169.254.169.254
    'fe80::1',
    'fe80::1%eth0',
    'fd12:3456::1',
    '64:ff9b::a00:1',
    '2002:7f00:1::1',
    '2001:db8::1',
    'ff02::1',
    '[::1]',
    'not-an-ip',
    '',
  ])('blocks %s', (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '172.15.255.255', '::ffff:8.8.8.8', '2606:4700:4700::1111', '2a00:1450:4009:81f::200e'])(
    'allows %s',
    (address) => {
      expect(isPublicAddress(address)).toBe(true);
    },
  );
});
