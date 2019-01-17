package nl.finalist.liferay.oidc;


import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.module.configuration.ConfigurationProvider;
import com.liferay.portal.kernel.security.auto.login.AutoLogin;
import com.liferay.portal.kernel.security.auto.login.BaseAutoLogin;
import com.liferay.portal.kernel.service.UserLocalService;

import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.Validator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @see LibAutoLogin
 */
@Component(
    immediate = true,
    service = AutoLogin.class,
    configurationPid = "nl.finalist.liferay.oidc.OpenIDConnectOCDConfiguration"
)
public class OpenIDConnectAutoLogin extends BaseAutoLogin {

    private static final Log LOG = LogFactoryUtil.getLog(OpenIDConnectAutoLogin.class);

    @Reference
    private Portal _portal;

    @Reference
    private UserLocalService _userLocalService;

    private LibAutoLogin libAutologin;

    private ConfigurationProvider _configurationProvider;

    @Reference
    protected void setConfigurationProvider(ConfigurationProvider configurationProvider) {
        _configurationProvider = configurationProvider;
    }

    public OpenIDConnectAutoLogin() {
        super();
    }

    @Activate
    protected void activate() {
        libAutologin = new LibAutoLogin(new Liferay70Adapter(_userLocalService, _configurationProvider));
    }

    // Stored last visited URL, when not yet signed in
    protected String redirect = "";

    @Override
    protected String[] doLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String currentURL = _portal.getCurrentURL(request);
        LOG.debug("[doLogin] currentURL: " + currentURL);
	String[] credentials = new String[3];
        credentials = libAutologin.doLogin(request, response);
	for(int i=0; i<3; i++) {
	    LOG.debug("[doLogin] credentials[" + i + "] = '" + credentials[i] + "'");
	}
	if(!currentURL.contains("login") && credentials[0].length() == 0) {
		// Store last URL when not yet signed in
		redirect = currentURL;
	} else if(currentURL.contains("login") && credentials[0].length() != 0) {
		// When login just accomplished, recall the stored URL
                if (Validator.isNotNull(redirect)) {
                        redirect = _portal.escapeRedirect(redirect);
                }
                else {
                        redirect = _portal.getPathMain();
                }
                request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirect);
                LOG.debug("[doLogin] redirect: " + redirect);
        } else {
                LOG.debug("[doLogin] Signed or URL contains login, redirect: " + redirect);
        }
	LOG.debug("[doLogin] Leaving credentials");
	return credentials;
    }
}
