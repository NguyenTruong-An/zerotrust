package com.zerotrust.risk.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class TimestampMySqlSupportTests {
    @TempDir Path directory;
    void withManifest(String field,Object replacement,String hashOverride,Runnable action) throws Exception {
        Map<String,Object> m=new LinkedHashMap<>();String run="619601bb-4b95-4ee6-97a0-3e144a8a05ae";
        m.put("approved",true);m.put("owner","POSTFIX-03B");m.put("run_uuid",run);m.put("container_name","zt-mysql-qa-postfix03b");m.put("endpoint","127.0.0.1:3310");
        m.put("schemas",List.of("pf03b_619601bb_baseline","pf03b_619601bb_lifecycle","pf03b_619601bb_identity"));
        if(field!=null)m.put(field,replacement);
        byte[] bytes=new ObjectMapper().writeValueAsBytes(m);Path path=directory.resolve("manifest.json");Files.write(path,bytes);
        Map<String,String> props=Map.of("postfix03b.native","APPROVED","postfix03b.runUUID",run,"postfix03b.manifest",path.toString(),
                "postfix03b.manifestSHA",hashOverride==null?HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)):hashOverride);
        Map<String,String> old=new HashMap<>();props.forEach((k,v)->{old.put(k,System.getProperty(k));System.setProperty(k,v);});
        try {action.run();}finally {old.forEach((k,v)->{if(v==null)System.clearProperty(k);else System.setProperty(k,v);});}
    }
    @Test void absentPermissionRejectsBeforeAnyConnection() {
        String previous=System.getProperty("postfix03b.native");System.setProperty("postfix03b.native","NOT_APPROVED");
        try {assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native permission missing");}
        finally {if(previous==null)System.clearProperty("postfix03b.native");else System.setProperty("postfix03b.native",previous);}
    }
    @Test void sourceOfManifestMustMatchExactApprovedHash() throws Exception {
        withManifest(null,null,"0".repeat(64),()->assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native manifest SHA mismatch"));
    }
    @Test void existing3309ResourceCannotBeReused() throws Exception {
        withManifest("container_name","zt-mysql-qa-postfix03a",null,()->assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native resource mismatch"));
    }
    @Test void historical3308PortCannotBeUsed() throws Exception {
        withManifest("endpoint","127.0.0.1:3308",null,()->assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native resource mismatch"));
    }
    @Test void differentOwnerCannotAuthorizeMutation() throws Exception {
        withManifest("owner","FIX-03",null,()->assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native owner/approval mismatch"));
    }
    @Test void missingApprovalCannotAuthorizeMutation() throws Exception {
        withManifest("approved",false,null,()->assertThatThrownBy(TimestampMySqlSupport::manifest).hasRootCauseMessage("Native owner/approval mismatch"));
    }
    @Test void otherSchemasAreRejectedWithoutConnecting() throws Exception {
        withManifest("schemas",List.of("risk_qa","risk_qa","risk_qa"),null,()->assertThatThrownBy(()->TimestampMySqlSupport.schemas(TimestampMySqlSupport.manifest())).hasMessage("Native schema allowlist mismatch"));
    }
}
