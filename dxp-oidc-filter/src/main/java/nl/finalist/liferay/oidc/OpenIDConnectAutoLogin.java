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

import com.liferay.portal.kernel.util.PortalUtil;
import com.liferay.portal.kernel.model.User;

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

    @Override
    protected String[] doLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String currentURL = _portal.getCurrentURL(request);
        LOG.debug("[doLogin] currentURL: " + currentURL);
	String[] credentials = { "", "", "" };
        credentials = libAutologin.doLogin(request, response);
	// Take care of redirection
	if(credentials != null && credentials[0].equals("@other_auth@")) {
		User user = PortalUtil.getUser(request);
		credentials[0] = "" + user.getUserId();
		LOG.debug("[doLogin] External authentication, userId: " + credentials[0]);
		String redirect = "/egissod/web/welcome";  //_portal.getPathMain();
		request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirect);
		LOG.debug("[doLogin] redirect: " + redirect);
	}
	else if(currentURL.contains("login") && credentials[0].length() != 0) {
		// User just SignedIn
		for(int i=0; i<credentials.length; i++) {
	            LOG.debug("[doLogin] credentials[" + i + "] = '" + credentials[i] + "'");
		}
                String redirect = _portal.getPathMain();
                request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirect);
                LOG.debug("[doLogin] redirect: " + redirect);
        }
	LOG.debug("[doLogin] Leaving credentials");
	return credentials;
    }
}
