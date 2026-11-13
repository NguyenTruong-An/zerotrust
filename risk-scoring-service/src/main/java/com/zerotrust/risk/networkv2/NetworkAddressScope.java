package com.zerotrust.risk.networkv2;

import com.zerotrust.risk.validation.IpAddressNormalizer;
import java.util.List;

/** No DNS lookup. Private, documentation and transition ranges cannot establish public history. */
final class NetworkAddressScope {
    private record Prefix(byte[] bytes, int bits) {
        static Prefix of(String cidr) {
            String[] parts = cidr.split("/");
            return new Prefix(IpAddressNormalizer.parseLiteral(parts[0]).getAddress(), Integer.parseInt(parts[1]));
        }
        boolean contains(byte[] address) {
            if (address.length != bytes.length) return false;
            for (int bit = 0; bit < bits; bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((address[bit / 8] & mask) != (bytes[bit / 8] & mask)) return false;
            }
            return true;
        }
    }
    private static final List<Prefix> EXCLUDED = List.of("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
            "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.168.0.0/16", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
            "240.0.0.0/4", "::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "fc00::/7",
            "fe80::/10", "fec0::/10", "ff00::/8", "2001::/23", "2001:db8::/32", "2002::/16")
            .stream().map(Prefix::of).toList();
    static boolean isPublic(String literal) {
        byte[] address = IpAddressNormalizer.parseLiteral(literal).getAddress();
        if (address.length == 16 && (address[0] & 0xe0) != 0x20) return false;
        return EXCLUDED.stream().noneMatch(prefix -> prefix.contains(address));
    }
}
