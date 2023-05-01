import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.calendar.CalendarScopes;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.sheets.v4.SheetsScopes;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* class to demonstarte use of Calendar events list API */
public class GoogleCredentialGenerator {
  /**
   * Global instance of the JSON factory.
   */
  private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
 
  /**
   * Global instance of the scopes required by this quickstart.
   * If modifying these scopes, delete your previously saved tokens/ folder.
   */
  private static final List<String> SCOPES = List.of(
    CalendarScopes.CALENDAR,
    GmailScopes.GMAIL_SEND,
    SheetsScopes.SPREADSHEETS
  );
 
  private static final String CLIENT_CREDENTIALS_FILE_PATH = "/google-client-credentials.json";

  private static final String AUTHORIZED_USER_CREDENTIALS_FILE_PATH = "/google-authorized-user-credentials.json";

  /**
   * Creates an authorized Credential object.
   *
   * @param HTTP_TRANSPORT The network HTTP Transport.
   * @return An authorized Credential object.
   * @throws IOException If the credentials.json file cannot be found.
   */
  private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT,
                                           GoogleClientSecrets clientSecrets)
      throws IOException {
    // Build flow and trigger user authorization request.
    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
        HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
        .setAccessType("offline")
        .build();
    LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
    Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");

    //returns an authorized Credential object.
    return credential;
  }

  private static String getProjectId() throws IOException {
    InputStream is = GoogleCredentialGenerator.class.getResourceAsStream(CLIENT_CREDENTIALS_FILE_PATH);
    String jsonTxt = IOUtils.toString(is, "UTF-8");
    return new JSONObject(jsonTxt).getJSONObject("web").getString("project_id");
  }

  public static void main(String... args) throws IOException, GeneralSecurityException {
    // Load client secrets.
    InputStream in = GoogleCredentialGenerator.class.getResourceAsStream(CLIENT_CREDENTIALS_FILE_PATH);
    if (in == null) {
      throw new FileNotFoundException("Resource not found: " + CLIENT_CREDENTIALS_FILE_PATH);
    }
    GoogleClientSecrets clientSecrets =
        GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

    // Build a new authorized API client service.
    final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
    Credential credential = getCredentials(HTTP_TRANSPORT, clientSecrets);
    JSONObject json = new JSONObject();
    try {
        json.put("type", "authorized_user");
        json.put("client_id", clientSecrets.getDetails().getClientId());
        json.put("project_id", getProjectId());
        json.put("auth_uri", "https://accounts.google.com/o/oauth2/auth");
        json.put("token_uri", "https://oauth2.googleapis.com/token");
        json.put("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs");
        json.put("client_secret", clientSecrets.getDetails().getClientSecret());
        json.put("redirect_uris", List.of("http://localhost"));
        json.put("access_token", credential.getAccessToken());
        json.put("refresh_token", credential.getRefreshToken());

    } catch (JSONException e) {
        e.printStackTrace();
    }

    try (PrintWriter out = new PrintWriter(new FileWriter(
        "src/main/resources" + AUTHORIZED_USER_CREDENTIALS_FILE_PATH
    ))) {
        out.write(json.toString());
    } catch (Exception e) {
        e.printStackTrace();
    }
  }
}