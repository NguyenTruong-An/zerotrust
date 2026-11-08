package com.zerotrust.keycloak.risk.config;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.function.Function;

/** File reference only in the Public Demo realm; never store a client secret in authenticator config. */
public final class PublicDemoServiceSecrets {
    public static final String SECRET_FILE="/run/secrets/risk-caller-client-secret";
    private final Map<String,String> environment;
    private final Function<String,String> reader;
    public PublicDemoServiceSecrets(){this(markers(),PublicDemoServiceSecrets::readFile);}
    private static Map<String,String> markers(){
        Map<String,String> selected=new HashMap<>();
        for(String key:List.of("PUBLIC_DEMO_MODE","PUBLIC_DEMO_ACADEMIC_READ_ONLY","PUBLIC_DEMO_RISK_CALLER_SECRET_FILE")){
            String value=System.getenv(key);if(value!=null)selected.put(key,value);
        }
        return selected;
    }
    PublicDemoServiceSecrets(Map<String,String> environment,Function<String,String> reader){this.environment=Map.copyOf(environment);this.reader=reader;}
    boolean required(){
        String mode=environment.getOrDefault("PUBLIC_DEMO_MODE","lab"),flag=environment.getOrDefault("PUBLIC_DEMO_ACADEMIC_READ_ONLY","");
        if(mode.equals("lab") && flag.isBlank())return false;
        check(mode.equals("public-demo") && flag.equals("true"));return true;
    }
    public void validateStartup(){if(required()){check(SECRET_FILE.equals(environment.get("PUBLIC_DEMO_RISK_CALLER_SECRET_FILE")));reader.apply(SECRET_FILE);}}
    String resolve(Map<String,String> config){
        String inline=config.get(RiskAuthenticatorConfigResolver.SERVICE_CLIENT_SECRET);
        String file=config.get(RiskAuthenticatorConfigResolver.SERVICE_CLIENT_SECRET_FILE);
        if(required()){
            validateStartup();check(inline==null || inline.isBlank());check(SECRET_FILE.equals(file));
            check(ServiceTokenConfig.DEFAULT_CLIENT_ID.equals(config.get(RiskAuthenticatorConfigResolver.SERVICE_CLIENT_ID)));
            for(String key:List.of(RiskAuthenticatorConfigResolver.SERVICE_BASE_URL,RiskAuthenticatorConfigResolver.TOKEN_ENDPOINT_URL)){
                try{var u=java.net.URI.create(config.get(key));String host=u.getHost();check("https".equals(u.getScheme()) && host!=null && u.getRawUserInfo()==null
                        && !host.equals("localhost") && !host.startsWith("127.") && !host.contains(":") && !host.equals("0.0.0.0") && !host.toLowerCase(java.util.Locale.ROOT).contains("lab"));}
                catch(RuntimeException ignored){throw rejected();}
            }
        }
        if(file!=null && !file.isBlank()) {check(inline==null || inline.isBlank());return reader.apply(file);}
        check(inline!=null && !inline.isBlank());return inline.trim(); // Legacy/Lab transport preserved.
    }
    public static String readFile(String location){
        try{
            Path path=Path.of(location);check(path.isAbsolute());
            BasicFileAttributes attributes=Files.readAttributes(path,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
            check(attributes.isRegularFile() && attributes.size()>=16 && attributes.size()<=4096);
            if(Files.getFileStore(path).supportsFileAttributeView(PosixFileAttributeView.class)){
                var permissions=Files.getPosixFilePermissions(path,LinkOption.NOFOLLOW_LINKS);
                check(permissions.stream().allMatch(p->p==PosixFilePermission.OWNER_READ || p==PosixFilePermission.OWNER_WRITE));
            }
            byte[] bytes;
            try(var stream=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){bytes=stream.readNBytes(4097);}
            check(bytes.length<=4096);
            String value=StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString();
            // A single terminal newline from a text-file writer is permitted; no multiline credentials.
            if(value.endsWith("\n"))value=value.substring(0,value.length()-1);
            check(value.length()>=16 && !value.isBlank() && value.chars().noneMatch(c->Character.isISOControl(c)));
            return value;
        }catch(Exception ignored){throw rejected();} // No path, contents or parser cause in failures.
    }
    private static void check(boolean valid){if(!valid)throw rejected();}
    private static RiskAuthenticatorConfigurationException rejected(){return new RiskAuthenticatorConfigurationException("Service secret configuration rejected (values redacted)");}
}
