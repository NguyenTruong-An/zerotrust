import org.flywaydb.core.Flyway;
import java.util.Properties;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
public class Migrate {
    public static void main(String[] args) throws Exception {
        Properties p=new Properties();try(var in=Files.newInputStream(Path.of("/run/demo/migration.properties"))){p.load(in);}
        if(new db.migration.V5__isolate_subject_identity().getChecksum()!=661092940)throw new IllegalStateException("V5_BUILD_CHECKSUM_DRIFT");
        var flyway=Flyway.configure().dataSource(p.getProperty("url"),p.getProperty("username"),p.getProperty("password"))
                .locations("classpath:db/migration").cleanDisabled(true).load();
        boolean pending=java.util.Arrays.stream(flyway.info().pending()).anyMatch(m->"5".equals(m.getVersion().getVersion()));
        if(pending){
            try(var c=DriverManager.getConnection(p.getProperty("url"),p.getProperty("username"),p.getProperty("password"));var s=c.createStatement();
                var r=s.executeQuery("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='demo_risk'")){
                r.next();if(r.getInt(1)!=0)throw new IllegalStateException("RISK_WRITERS_NOT_QUIESCED");
            }
            System.setProperty("zerotrust.migration.subject-identity.writers-quiesced","true");
        }
        flyway.migrate();flyway.validate();System.out.println("Risk V1-V5 migrated and validated; V5=661092940");
    }
}
