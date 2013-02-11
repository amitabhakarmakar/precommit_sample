mport static com.hbo.it.go.profile.constants.AffiliateAuthConstants.ASSERTION_CONSUMER_SERVICE_URL;

@Service("authnRequestService")
public class sample implements AuthnRequestService {

	private static final Logger log = LoggerFactory
			.getLogger(AuthnRequestServiceImpl.class);

	@Autowired
	private AffiliateAuthService affiliateAuthService;

	@Autowired
	private AffiliateInfoService affiliateInfoService;

	public AuthnRequestInfo generateAuthnRequest(String affiliateCode,
			String serviceCode, String platformCode, String deviceCode,
			boolean forceAuthn, String relayState, String cancelURL, String host) {

		AuthnRequestInfo authnRequestInfo = new AuthnRequestInfo();

		authnRequestInfo.setAffiliateInfo(affiliateInfoService
				.getAffiliateInfo(affiliateCode, platformCode));
		authnRequestInfo.setServiceCode(serviceCode);
		authnRequestInfo.setPlatformCode(platformCode);
		authnRequestInfo.setDeviceCode(deviceCode);
		authnRequestInfo.setRelayState(relayState);
		authnRequestInfo.setCancelURL(cancelURL);
		authnRequestInfo.setHost(host);
		configureAuthnUrl(authnRequestInfo);

		authnRequestInfo.setAuthnContent(affiliateAuthService.getAuthnRequest(
				affiliateCode, serviceCode, host, relayState, platformCode,
				deviceCode));

		String authnHttpMethod = authnRequestInfo.getAffiliateInfo()
				.getAffiliateConfiguration().getAuthnHttpMethod();

		if (HttpComponent.POST.equalsIgnoreCase(authnHttpMethod)) {
			generatePostAuthnRequest(authnRequestInfo);
		} else {
			generateGetAuthnRequest(authnRequestInfo);

		}

		return authnRequestInfo;
	}

	private AuthnRequestInfo generatePostAuthnRequest(
			AuthnRequestInfo authnRequestInfo) {

		if (log.isDebugEnabled())
			log.debug("browser posting to url [" + authnRequestInfo.getUrl()
					+ "]");

		String relayStateName = authnRequestInfo.getAffiliateInfo()
				.getAffiliateConfiguration().getRelayStateName();
		if (StringUtils.isBlank(relayStateName)) {
			relayStateName = SAML2Constants.RELAY_STATE;
		}
		authnRequestInfo.setSamlMessageName(SAML2Constants.SAML_REQUEST);
		authnRequestInfo
				.setSamlMessageValue(authnRequestInfo.getAuthnContent());
		authnRequestInfo.setRelayStateName(relayStateName);
		return authnRequestInfo;

	}

	private void generateGetAuthnRequest(AuthnRequestInfo authnRequestInfo) {
		// Only add authnContent if affiliate uses authnRequest
		// otherwise just add the RelayState GET the url

		String authnContent = affiliateAuthService.getAuthnRequest(
				authnRequestInfo.getAffiliateInfo().getCode(),
				authnRequestInfo.getServiceCode(), authnRequestInfo.getHost(),
				authnRequestInfo.getRelayState(),
				authnRequestInfo.getPlatformCode(),
				authnRequestInfo.getDeviceCode());

		String url = authnRequestInfo.getUrl();
		AffiliateInfo affiliateInfo = authnRequestInfo.getAffiliateInfo();
		if (affiliateInfo.getAffiliateConfiguration().isUsesAuthnRequest()) {
			url += "?" + authnContent;
		} else {
			url += "&" + SAML2Constants.RELAY_STATE + "="
					+ authnRequestInfo.getRelayState();
		}

		String cancelURL = authnRequestInfo.getCancelURL();
		if (cancelURL != null) {
			url += "&" + QueryConstants.QUERY_PARAM_CANCEL_URL + "="
					+ cancelURL;
		}

		if (log.isDebugEnabled())
			log.debug("browser getting from url [" + url + "]");

		authnRequestInfo.setRedirectUrl(url);

	}

	private void configureAuthnUrl(AuthnRequestInfo authnRequestInfo) {
		AffiliateInfo affiliateInfo = authnRequestInfo.getAffiliateInfo();
		String authnUrl = affiliateInfo.getAffiliateConfiguration()
				.getEnvironmentConfig().getAuthNUrl();
		authnRequestInfo.setUrl(configureAuthnUrl(authnUrl, authnRequestInfo));

	}

	private String configureAuthnUrl(String url,
			AuthnRequestInfo authnRequestInfo) {
		url = PropertyUtil.replace(url, ASSERTION_CONSUMER_SERVICE_URL,
				getAssertionConsumerServiceURL(authnRequestInfo));
		url = PropertyUtil.replace(url,
				QueryConstants.QUERY_PARAM_PLATFORM_CODE, authnRequestInfo
						.getPlatformCode().toLowerCase());
		url = PropertyUtil.replace(url,
				QueryConstants.QUERY_PARAM_SERVICE_CODE, authnRequestInfo
						.getServiceCode().toLowerCase());
		url = PropertyUtil.replace(url, WEB_SERVER_HOST, CommonsUtil
				.getWebServerHostfromProfileHost(authnRequestInfo.getHost()));

		Properties properties = new Properties();

		AffiliateInfo affiliateInfo = authnRequestInfo.getAffiliateInfo();

		properties = ReflectionUtil.getBeanStringProperites(properties,
				affiliateInfo);
		properties = ReflectionUtil.getBeanStringProperites(properties,
				affiliateInfo.getAffiliateConfiguration());

		Map<String, Object> deviceMap = affiliateInfo
				.getAffiliateConfiguration().getDeviceMap();
		// get device map and replace key with value for deviceMapCode param.
		if (deviceMap != null) {
			properties.put("deviceMapCode",
					(String) deviceMap.get(authnRequestInfo.getDeviceCode()));

		}
		return replaceStringProperties(url, properties);

	}

	private String replaceStringProperties(String target, Properties properties) {
		PropertyPlaceholderHelper propertyPlaceholderHelper = new PropertyPlaceholderHelper(
				"#{", "}");

		return propertyPlaceholderHelper
				.replacePlaceholders(target, properties);
	}

	private String getAssertionConsumerServiceURL(
			AuthnRequestInfo authnRequestInfo) {
		// Map<String,Object> properties =
		// getPropertyHelper().getProperties(affiliate);
		AffiliateInfo affiliateInfo = authnRequestInfo.getAffiliateInfo();

		String loginUriPath = LoginType.IFRAME_LOGIN_URI_PATH;
		if (affiliateInfo.isLoginRedirect()) {
			loginUriPath = LoginType.REDIRECT_LOGIN_URI_PATH;
		}

		String service = authnRequestInfo.getServiceCode();
		String host = authnRequestInfo.getHost();

		if (service == null && host == null) {
			return affiliateInfo.getAffiliateConfiguration()
					.getConsumerAssertUrl();
		} else {
			StringBuilder stb = new StringBuilder();
			stb.append(host);
			stb.append("/");
			stb.append(LoginType.LOGIN_REST_SERVICE_PATH);
			stb.append("/");
			stb.append(loginUriPath);
			stb.append("/");
			stb.append(affiliateInfo.getCode());
			stb.append("?");
			stb.append(QueryConstants.QUERY_PARAM_SERVICE_CODE);
			stb.append("=");
			stb.append(service);

			return stb.toString();

		}
	}

}

