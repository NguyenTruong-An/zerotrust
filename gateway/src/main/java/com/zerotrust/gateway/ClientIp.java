package com.zerotrust.gateway;

import java.net.*;
import java.util.Arrays;

/** IP literals only; representation matches Risk's normalizer. Never resolve a hostname. */
final class ClientIp {
    private ClientIp() { }
    static InetAddress parse(String value) {
        try {
            if (value == null || value.isEmpty() || value.length() > 45) throw new IllegalArgumentException();
            if (!value.contains(":")) {
                if (!value.matches("[0-9.]+")) throw new IllegalArgumentException();
                String[] parts = value.split("\\.", -1);
                if (parts.length != 4) throw new IllegalArgumentException();
                byte[] bytes = new byte[4];
                for (int i=0;i<4;i++) {
                    if (!parts[i].matches("[0-9]{1,3}") || Integer.parseInt(parts[i])>255) throw new IllegalArgumentException();
                    bytes[i]=(byte)Integer.parseInt(parts[i]);
                }
                return InetAddress.getByAddress(bytes);
            }
            if (!value.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException();
            if (value.contains(".")) parse(value.substring(value.lastIndexOf(':')+1));
            InetAddress address=InetAddress.getByName(value); // Colon + literal whitelist prevents DNS.
            if (!(address instanceof Inet6Address)) throw new IllegalArgumentException();
            return address;
        } catch (RuntimeException | UnknownHostException ignored) { throw new IllegalArgumentException("Invalid IP literal"); }
    }
    static String normalize(String value) { return parse(value).getHostAddress(); }

    record Cidr(byte[] network, int prefix) {
        Cidr { network=masked(network,prefix); }
        static Cidr parse(String value) {
            try {
                String[] parts=value.split("/",-1);
                if (parts.length!=2 || !parts[1].matches("[0-9]{1,3}")) throw new IllegalArgumentException();
                byte[] address=ClientIp.parse(parts[0]).getAddress(); int bits=Integer.parseInt(parts[1]);
                if (bits<1 || bits>address.length*8) throw new IllegalArgumentException(); // Never trust the whole Internet.
                return new Cidr(address,bits);
            } catch (RuntimeException ignored) { throw new IllegalArgumentException("Invalid trusted proxy CIDR"); }
        }
        boolean contains(InetAddress address) {
            return address.getAddress().length==network.length && Arrays.equals(network,masked(address.getAddress(),prefix));
        }
        private static byte[] masked(byte[] bytes,int bits) {
            byte[] result=bytes.clone(); int full=bits/8, remainder=bits%8;
            if (remainder>0) { result[full]&=(byte)(0xff << (8-remainder));full++; }
            Arrays.fill(result,full,result.length,(byte)0);return result;
        }
    }
}
