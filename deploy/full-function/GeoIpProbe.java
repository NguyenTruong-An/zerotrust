import com.maxmind.db.Reader;
import com.maxmind.geoip2.DatabaseReader;
import com.zerotrust.risk.config.*;
import com.zerotrust.risk.domain.*;
import com.zerotrust.risk.service.*;
import java.math.BigDecimal;
import java.net.InetAddress;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Private offline probe using the actual deployed provider/calculator classes. */
public class GeoIpProbe {
    static Instant now=Instant.now();
    static Map<String,Object> metadata(Path file,String type) throws Exception {
        try(var reader=new Reader(file.toFile())) {
            var m=reader.getMetadata();var built=m.buildTime();
            if(!m.databaseType().equals("GeoLite2-"+type) || m.binaryFormatMajorVersion()!=2
                    || built.isAfter(now.plusSeconds(86400))
                    || built.isBefore(now.minus(Duration.ofDays(30))))
                throw new IllegalArgumentException("Dataset type/format/freshness rejected");
            return Map.of("database_type",m.databaseType(),"build_at",built.toString(),
                    "ip_version",m.ipVersion(),"binary_format",m.binaryFormatMajorVersion(),
                    "file_bytes",Files.size(file));
        }
    }
    public static void main(String[] args) throws Exception {
        if(args.length>2)now=Instant.parse(args[2]); // declared offline freshness-clock test only
        var dir=Path.of(args[0]);var result=new LinkedHashMap<String,Object>();
        result.put("city",metadata(dir.resolve("GeoLite2-City.mmdb"),"City"));
        result.put("asn",metadata(dir.resolve("GeoLite2-ASN.mmdb"),"ASN"));
        var g=new GeoIpProperties();g.setEnabled(true);g.setCityDatabasePath(dir.resolve("GeoLite2-City.mmdb").toString());g.setAsnDatabasePath(dir.resolve("GeoLite2-ASN.mmdb").toString());
        var network=new NetworkRiskProperties();network.setEnabled(true);network.setDefaultScore(new BigDecimal("50"));
        network.setElevatedScore(new BigDecimal("50"));network.setHighScore(new BigDecimal("100"));
        var policy=new RiskPolicyProperties();var w=policy.getWeights();
        w.setDevice(new BigDecimal(".25"));w.setNetwork(new BigDecimal(".25"));w.setTemporal(new BigDecimal(".25"));w.setAuthenticationHistory(new BigDecimal(".25"));
        policy.getThresholds().setMediumMinimum(new BigDecimal("40"));policy.getThresholds().setHighMinimum(new BigDecimal("75"));
        var scorer=new RiskScoringService(policy);
        var provider=new MaxMindGeoIpProvider(g);
        try(var directCity=new DatabaseReader.Builder(dir.resolve("GeoLite2-City.mmdb").toFile()).build();
            var directAsn=new DatabaseReader.Builder(dir.resolve("GeoLite2-ASN.mmdb").toFile()).build()) {
            var calculator=new NetworkRiskCalculator(network,provider);var rows=new ArrayList<Map<String,Object>>();
            for(String ip:List.of("8.8.8.8","8.8.4.4","2001:4860:4860::8888","1.1.1.1","2606:4700:4700::1111","192.0.2.44","10.2.3.4","127.0.0.1","::1","fd00::1","2001:db8::1")) {
                var row=new LinkedHashMap<String,Object>();row.put("test_ip",ip);
                var lookup=provider.lookup(ip);row.put("direct_provider_status",lookup.status().name());
                if(lookup.location()!=null) {
                    var l=lookup.location();row.put("location",l);
                    var city=directCity.tryCity(InetAddress.getByName(ip));var asn=directAsn.tryAsn(InetAddress.getByName(ip));
                    if(city.isEmpty() || !Objects.equals(city.get().country().isoCode(),l.countryCode())
                            || !Objects.equals(asn.map(a->a.autonomousSystemNumber()).orElse(null),l.autonomousSystemNumber()))
                        throw new IllegalStateException("Provider/direct reader mismatch");
                    row.put("independent_reader_match",true);
                }
                var n=calculator.calculate(new LoginContext("geoip-probe",UUID.randomUUID().toString(),"zerotrust-spa",ip,"declared offline public/reserved fixtures",null,Instant.now()));
                row.put("network",n);row.put("weighted_network",n.riskScore()==null?null:n.riskScore().multiply(new BigDecimal(".25")));
                if(n.riskScore()!=null)row.put("isolated_numeric_score_DTH_zero",scorer.evaluate(new RiskFactors(BigDecimal.ZERO,n.riskScore(),BigDecimal.ZERO,BigDecimal.ZERO)));
                rows.add(row);
            }
            result.put("lookups",rows);result.put("country_asn_policy","Only country code influences GEOIP policy; empty country/CIDR lists in this declared offline fixture; ASN/city are metadata");
            result.put("not_browser_or_live_policy",true);
        } finally { provider.close(); }
        Files.writeString(Path.of(args[1]),new tools.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result));
        System.out.println("PASS real City/ASN metadata, independent lookups and unchanged provider/calculator/weighted B0 probe");
    }
}
