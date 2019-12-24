/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.http;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.springframework.security.oauth2.core.oidc.TestOidcIdTokens.idToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests for {@link OAuth2LoginBeanDefinitionParser}.
 *
 * @author Ruby Hartono
 */
public class OAuth2LoginBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/OAuth2LoginBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

	@Autowired
	private MockMvc mvc;

	// gh-5347
	@Test
	public void requestWhenSingleClientRegistrationThenAutoRedirect() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/oauth2/authorization/google-login"));
	}

	// gh-5347
	@Test
	public void requestWhenSingleClientRegistrationAndRequestFaviconNotAuthenticatedThenRedirectDefaultLoginPage()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/favicon.ico").accept(new MediaType("image", "*"))).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	// gh-6812
	@Test
	public void requestWhenSingleClientRegistrationAndRequestXHRNotAuthenticatedThenDoesNotRedirectForAuthorization()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/").header("X-Requested-With", "XMLHttpRequest")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void requestWhenSingleClientRegistrationWithNonExistanceAuthenticationThenRedirectToDefaultLoginError()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void successLoginWhenSingleClientRegistrationThenRedirectToDefaultUrl() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"));
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(ClientRegistration registration,
			String... scopes) {
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.clientId(registration.getClientId()).state("state123").redirectUri("http://localhost")
				.attributes(Collections.singletonMap(OAuth2ParameterNames.REGISTRATION_ID,
						registration.getRegistrationId()))
				.scope(scopes).build();
	}

	public static class DummyAccessTokenResponse
			implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

		public static final String ACCESS_TOKEN_VALUE = "accessToken123";

		@Override
		public OAuth2AccessTokenResponse getTokenResponse(
				OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			Map<String, Object> additionalParameters = new HashMap<>();
			if (authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes()
					.contains("openid")) {
				additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
			}
			return OAuth2AccessTokenResponse.withToken(ACCESS_TOKEN_VALUE).tokenType(OAuth2AccessToken.TokenType.BEARER)
					.additionalParameters(additionalParameters).build();
		}
	}

	public static class DummyOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

		@Override
		public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
			Map<String, Object> userAttributes = Collections.singletonMap("name", "spring");
			return new DefaultOAuth2User(Collections.singleton(new OAuth2UserAuthority(userAttributes)), userAttributes,
					"name");
		}

	}

	public static class DummyOAuth2OidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

		@Override
		public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
			OidcIdToken idToken = idToken().build();
			return new DefaultOidcUser(Collections.singleton(new OidcUserAuthority(idToken)), idToken);
		}

	}
}
