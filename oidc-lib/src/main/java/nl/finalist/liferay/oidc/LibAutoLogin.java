package nl.finalist.liferay.oidc;

import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;

import nl.finalist.liferay.oidc.providers.UserInfoProvider;

/**
 * AutoLogin for OpenID Connect 1.0
 * This class should be used in tandem with the OpenIDConnectFilter. That filter will do the OAuth conversation and
 * set a session attribute containing the UserInfo object (the claims).
 * This AutoLogin will use the claims to find a corresponding Liferay user or create a new one if none found.
 */
public class LibAutoLogin {

    private final LiferayAdapter liferay;

    public LibAutoLogin(LiferayAdapter liferay) {
        this.liferay = liferay;
        liferay.info("Initialized LibAutoLogin with Liferay API: " + liferay.getClass().getName());
    }

    private String jsonProcMap(String jsonInfo, Map<String, String> info) {
        String[] map_fields = {"sub", "access_token"};
        for(Entry<String, String> entry : info.entrySet()) {
            String entryKey = entry.getKey();
            String entryVal = "";
            if(entry.getValue() instanceof String) {
                entryVal = entry.getValue();
            } else {
                liferay.debug("Skipping no String value for key: '" + entryKey + "'");
            }
            for(int i=0; i<map_fields.length; i++) {
                if(entryKey.equals(map_fields[i])) {
	            String jsonItem = "";
                    jsonItem = "\"" + entryKey + "\": " +
                               "\"" + entryVal + "\"";
                    if(jsonInfo.equals("{")) {
                        jsonInfo += jsonItem;
                    } else {
                        jsonInfo += ", " + jsonItem;
                    }
                    break;
                } else {
                    continue;
                }
            }
        }
        return jsonInfo;
    }

    private String jsonUserInfo(Map<String, String> userInfo,
		                Map<String, String> userAccessToken) {
        String jsonUserInfo = "{";
        jsonUserInfo = jsonProcMap(jsonUserInfo, userInfo);
        jsonUserInfo = jsonProcMap(jsonUserInfo, userAccessToken);
	jsonUserInfo += "}";
        return jsonUserInfo;
   }

    private String jsonUserInfo(Map<String,String> userInfo) {
        String jsonUserInfo = "{";
        int i=0;
        for (Entry<String, String> entry : userInfo.entrySet()) {
	    String jsonItem = "";
	    // Process only String values
	    if(entry.getValue() instanceof String) {
                jsonItem = "\"" + entry.getKey() + "\": " +
                           "\"" + entry.getValue() + "\"";
	    } else {
                jsonItem = "\"" + entry.getKey() + "\": " +
                           "\"<unsupported type>\"";
            }
            if(i == 0) {
              jsonUserInfo += jsonItem;
              i++;
            } else {
              jsonUserInfo += ", " + jsonItem;
            }
        }
        jsonUserInfo += "}";
        return jsonUserInfo;
   }

    public String[] doLogin(HttpServletRequest request, HttpServletResponse response) {
    	String[] userResponse = null;

        long companyId = liferay.getCompanyId(request);

        OIDCConfiguration oidcConfiguration = liferay.getOIDCConfiguration(companyId);

        if (oidcConfiguration.isEnabled()) {
            if(liferay.isUserLoggedIn(request)) {
                // User is authenticated by another authentication source
                liferay.trace("[doLogin] User already authenticated by another authentication source");
                userResponse = new String[]{ "@other_auth@", null, null};
            } else {
                HttpSession session = request.getSession();
                Map<String, String> userInfo = (Map<String, String>) session.getAttribute(
                        LibFilter.OPENID_CONNECT_SESSION_ATTR);
                Map<String, String> userAccessToken =
                        (Map<String, String>) session.getAttribute(LibFilter.OPENID_CONNECT_ACCESS_TOKEN);

                UserInfoProvider provider = ProviderFactory.getOpenIdProvider(oidcConfiguration.providerType());

                 if (userInfo == null) {
                     // Normal flow, apparently no current OpenID conversation
                     liferay.trace("No current OpenID Connect conversation, no auto login");
                 } else if (StringUtils.isBlank(provider.getEmail(userInfo))) {
                     liferay.error("Unexpected: OpenID Connect UserInfo does not contain email field. " +
                                   "Cannot correlate to Liferay user. UserInfo: " + userInfo);
                 } else {
                     liferay.trace("Found OpenID Connect session attribute, userinfo: " + userInfo);
                     String oidcData = jsonUserInfo(userInfo, userAccessToken);
                     String emailAddress = provider.getEmail(userInfo);
                     String givenName = provider.getFirstName(userInfo);
                     String familyName = provider.getLastName(userInfo);

                     String userId = liferay.createOrUpdateUser(companyId, emailAddress, givenName, familyName, oidcData);
                     liferay.trace("Returning credentials for userId " + userId + ", email: " + emailAddress);
                 
                     userResponse = new String[]{userId, UUID.randomUUID().toString(), "false"};
                }
            }
	} else {
            liferay.trace("OpenIDConnectAutoLogin not enabled for this virtual instance. Will skip it.");
        }
        return userResponse;
    }
}
