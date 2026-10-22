import java.net.URI;
import javax.net.ssl.HttpsURLConnection;
public class Health {
    public static void main(String[] args) throws Exception {
        var c=(HttpsURLConnection)URI.create(args[0]).toURL().openConnection();
        c.setConnectTimeout(3000);c.setReadTimeout(3000);
        if(c.getResponseCode()!=Integer.parseInt(args[1]))System.exit(1);
        c.disconnect();
    }
}
