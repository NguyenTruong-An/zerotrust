package com.zerotrust.zerotrust.config;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.*;
import java.nio.file.*;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class PublicDemoSecretFilesTest {
    @ParameterizedTest @ValueSource(strings={"NONE","DB_PASSWORD","KEYCLOAK_ADMIN_CLIENT_SECRET","PORTAL_RISK_CLIENT_SECRET"})
    void everySecretLoadsFromConfigTreeAndMissingOneFailsRedacted(String missing,@TempDir Path directory,CapturedOutput output)throws Exception{
        Map<String,String> names=Map.of("DB_PASSWORD","spring.datasource.password","KEYCLOAK_ADMIN_CLIENT_SECRET","keycloak.admin.client-secret","PORTAL_RISK_CLIENT_SECRET","app.risk-admin.client-secret");
        var nonsecret=new ArrayList<String>();
        for(String entry:PublicDemoStartupConfigurationTest.VALID){
            String[] pair=entry.split("=",2);String target=names.get(pair[0]);
            if(target==null)nonsecret.add(entry);else if(!missing.equals(pair[0]))Files.writeString(directory.resolve(target),pair[1]);
        }
        new ApplicationContextRunner().withInitializer(c->{new ConfigDataApplicationContextInitializer().initialize(c);new PublicDemoStartupInitializer().initialize(c);})
                .withUserConfiguration(PublicDemoStartupConfigurationTest.MockDatabase.class)
                .withPropertyValues(nonsecret.toArray(String[]::new)).withPropertyValues("spring.config.import=configtree:"+directory.toString().replace('\\','/')+"/")
                .run(c->{if(missing.equals("NONE"))assertThat(c).hasNotFailed();else assertThat(c).hasFailed();});
        assertThat(output.getAll()).doesNotContain(PublicDemoStartupConfigurationTest.SECRET);
    }
}
