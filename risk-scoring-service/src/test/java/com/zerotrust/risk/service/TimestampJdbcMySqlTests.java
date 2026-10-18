package com.zerotrust.risk.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import com.zerotrust.risk.domain.DeviceTrustTimestamp;
import java.sql.Timestamp;
import java.time.Instant;
import static org.assertj.core.api.Assertions.*;

@EnabledIfSystemProperty(named="postfix03b.native",matches="APPROVED")
class TimestampJdbcMySqlTests {
    @Test void actualJdbcAndServerRoundingAreRecordedAndCanonicalMicrosecondsRoundTrip() throws Exception {
        TimestampMySqlSupport.before();
        try(var c=TimestampMySqlSupport.connect()) {
            String original=TimestampMySqlSupport.scalar(c,"SELECT @@session.sql_mode");
            assertThat(original).doesNotContain("TIME_TRUNCATE_FRACTIONAL");
            for(int nanos:new int[]{0,123456000,123456001,123456499,123456500,123456501,123456789,123456999,999999499,999999500,999999999}) {
                Instant input=TimestampLifecyclePrecisionContract.at(nanos),canonical=DeviceTrustTimestamp.canonical(input);
                try(var p=c.prepareStatement("SELECT CAST(? AS DATETIME(6))")) {
                    p.setTimestamp(1,Timestamp.from(input));try(var r=p.executeQuery()){r.next();assertThat(r.getTimestamp(1).toInstant()).isEqualTo(canonical);}
                    p.setTimestamp(1,Timestamp.from(canonical));try(var r=p.executeQuery()){r.next();assertThat(r.getTimestamp(1).toInstant()).isEqualTo(canonical);}
                }
                String text=input.toString().replace('T',' ').replace("Z","");
                if(nanos==0)text+=".000000000";
                try(var p=c.prepareStatement("SELECT CAST(? AS DATETIME(6))")) {
                    p.setString(1,text);try(var r=p.executeQuery()){r.next();assertThat(r.getTimestamp(1).toInstant()).isEqualTo(canonical);}
                }
                System.out.println("POSTFIX03B_JDBC input="+input+" canonical="+canonical+" mode=round");
            }
            // Connection-local diagnostic only; the connection is closed and no rows are written.
            try(var s=c.createStatement()){s.execute("SET SESSION sql_mode=CONCAT(@@session.sql_mode,',TIME_TRUNCATE_FRACTIONAL')");}
            try(var p=c.prepareStatement("SELECT CAST(? AS DATETIME(6))")) {
                p.setString(1,"2026-10-15 00:00:00.123456789");try(var r=p.executeQuery()){r.next();assertThat(r.getTimestamp(1).toInstant()).isEqualTo(TimestampLifecyclePrecisionContract.at(123456000));}
                p.setString(1,"2026-10-15 00:00:00.123457");try(var r=p.executeQuery()){r.next();assertThat(r.getTimestamp(1).toInstant()).isEqualTo(TimestampLifecyclePrecisionContract.at(123457000));}
            }
        } finally {TimestampMySqlSupport.after();}
    }
}
