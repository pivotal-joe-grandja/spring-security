/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core.oidc.discovery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientResponseException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DefaultOidcDiscoveryClient}.
 *
 * @author Joe Grandja
 */
public class DefaultOidcDiscoveryClientTests {

	private static final String DEFAULT_RESPONSE =
			"{\n"
			+ "    \"issuer\": \"https://example.com\", \n"
			+ "    \"authorization_endpoint\": \"https://example.com/o/oauth2/v2/auth\", \n"
			+ "    \"token_endpoint\": \"https://example.com/oauth2/v4/token\", \n"
			+ "    \"token_endpoint_auth_methods_supported\": [\n"
			+ "        \"client_secret_post\", \n"
			+ "        \"client_secret_basic\"\n"
			+ "    ], \n"
			+ "    \"token_endpoint_auth_signing_alg_values_supported\": [\n"
			+ "        \"RS256\", \n"
			+ "        \"ES256\"\n"
			+ "    ], \n"
			+ "    \"userinfo_endpoint\": \"https://example.com/oauth2/v3/userinfo\", \n"
			+ "    \"jwks_uri\": \"https://example.com/oauth2/v3/certs\", \n"
			+ "    \"response_types_supported\": [\n"
			+ "        \"code\", \n"
			+ "        \"token\", \n"
			+ "        \"id_token\", \n"
			+ "        \"code token\"\n"
			+ "    ], \n"
			+ "    \"grant_types_supported\": [\n"
			+ "        \"authorization_code\", \n"
			+ "        \"implicit\"\n"
			+ "    ], \n"
			+ "    \"scopes_supported\": [\n"
			+ "        \"openid\", \n"
			+ "        \"email\", \n"
			+ "        \"profile\"\n"
			+ "    ], \n"
			+ "    \"claims_supported\": [\n"
			+ "        \"aud\", \n"
			+ "        \"email\", \n"
			+ "        \"exp\", \n"
			+ "        \"iat\", \n"
			+ "        \"iss\", \n"
			+ "        \"name\", \n"
			+ "        \"sub\"\n"
			+ "    ], \n"
			+ "    \"subject_types_supported\": [\n"
			+ "        \"public\"\n"
			+ "    ], \n"
			+ "    \"id_token_signing_alg_values_supported\": [\n"
			+ "        \"RS256\", \n"
			+ "        \"ES256\"\n"
			+ "    ], \n"
			+ "    \"id_token_encryption_alg_values_supported\": [\n"
			+ "        \"RSA1_5\", \n"
			+ "        \"A128KW\"\n"
			+ "    ], \n"
			+ "    \"id_token_encryption_enc_values_supported\": [\n"
			+ "        \"A128CBC-HS256\", \n"
			+ "        \"A128GCM\"\n"
			+ "    ], \n"
			+ "    \"check_session_iframe\": \"https://example.com/oauth2/v3/check_session\", \n"
			+ "    \"end_session_endpoint\": \"https://example.com/oauth2/v3/end_session\"\n"
			+ "}";

	private DefaultOidcDiscoveryClient discoveryClient = new DefaultOidcDiscoveryClient();
	private ObjectMapper mapper = new ObjectMapper();
	private Map<String, Object> jsonResponse;
	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.jsonResponse = this.mapper.readValue(DEFAULT_RESPONSE, new TypeReference<Map<String, Object>>(){});
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void discoverWhenIssuerIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.discoveryClient.discover(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void discoverWhenRequestCreatedThenCorrectAttributesSet() throws Exception {
		String issuer = this.server.url("/").toString();
		this.jsonResponse.put(OidcProviderMetadataClaimNames.ISSUER, issuer);
		String jsonContent = this.mapper.writeValueAsString(this.jsonResponse);

		this.server.enqueue(new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(jsonContent));

		this.discoveryClient.discover(issuer);

		RecordedRequest recordedRequest = this.server.takeRequest();

		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON.toString());
		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(issuer + ".well-known/openid-configuration");
	}

	@Test
	public void discoverWhenIssuerHasPathThenRequestContainsPath() throws Exception {
		String issuer = this.server.url("/path").toString();
		this.jsonResponse.put(OidcProviderMetadataClaimNames.ISSUER, issuer);
		String jsonContent = this.mapper.writeValueAsString(this.jsonResponse);

		this.server.enqueue(new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(jsonContent));

		this.discoveryClient.discover(issuer);

		RecordedRequest recordedRequest = this.server.takeRequest();

		assertThat(recordedRequest.getRequestUrl().toString()).isEqualTo(issuer + "/.well-known/openid-configuration");
	}

	@Test
	public void discoverWhenErrorResponse500ThenThrowHttpServerErrorException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));

		String issuer = this.server.url("/").toString();

		assertThatThrownBy(() -> this.discoveryClient.discover(issuer))
				.isInstanceOf(HttpServerErrorException.class);
	}

	@Test
	public void discoverWhenErrorResponse400ThenThrowHttpClientErrorException() {
		this.server.enqueue(new MockResponse().setResponseCode(400));

		String issuer = this.server.url("/").toString();

		assertThatThrownBy(() -> this.discoveryClient.discover(issuer))
				.isInstanceOf(HttpClientErrorException.class);
	}

	@Test
	public void discoverWhenSuccessResponseNot200ThenThrowRestClientResponseException() {
		this.server.enqueue(new MockResponse().setResponseCode(204));

		String issuer = this.server.url("/").toString();

		assertThatThrownBy(() -> this.discoveryClient.discover(issuer))
				.isInstanceOf(RestClientResponseException.class)
				.hasMessage("The OpenID Provider Configuration Response did not return a 200 status -> returned 204");
	}

	@Test
	public void discoverWhenSuccessResponseNotMatchingIssuerThenThrowIllegalStateException() {
		this.server.enqueue(new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(DEFAULT_RESPONSE));

		String issuer = this.server.url("/").toString();

		assertThatThrownBy(() -> this.discoveryClient.discover(issuer))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("The issuer \"https://example.com\" in the OpenID Provider Configuration did not match the requested issuer");
	}

	@Test
	public void discoverWhenResponseHasFullConfigurationThenAllAccessorsReturnClaimValues() throws Exception {
		String issuer = this.server.url("/").toString();
		this.jsonResponse.put(OidcProviderMetadataClaimNames.ISSUER, issuer);
		String jsonContent = this.mapper.writeValueAsString(this.jsonResponse);

		this.server.enqueue(new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(jsonContent));

		OidcProviderConfiguration providerConfiguration = this.discoveryClient.discover(issuer);

		assertThat(providerConfiguration).isNotNull();
		assertThat(providerConfiguration.getClaims()).hasSize(17);
		assertThat(providerConfiguration.getIssuer().toString()).isEqualTo(issuer);
		assertThat(providerConfiguration.getAuthorizationEndpoint().toString()).isEqualTo("https://example.com/o/oauth2/v2/auth");
		assertThat(providerConfiguration.getTokenEndpoint().toString()).isEqualTo("https://example.com/oauth2/v4/token");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).containsExactly("client_secret_post", "client_secret_basic");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationSigningAlgorithms()).containsExactly("RS256", "ES256");
		assertThat(providerConfiguration.getUserInfoEndpoint().toString()).isEqualTo("https://example.com/oauth2/v3/userinfo");
		assertThat(providerConfiguration.getJwksUri().toString()).isEqualTo("https://example.com/oauth2/v3/certs");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code", "token", "id_token", "code token");
		assertThat(providerConfiguration.getGrantTypes()).containsExactly("authorization_code", "implicit");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getIdTokenSigningAlgorithms()).containsExactly("RS256", "ES256");
		assertThat(providerConfiguration.getIdTokenKeyEncryptionAlgorithms()).containsExactly("RSA1_5", "A128KW");
		assertThat(providerConfiguration.getIdTokenContentEncryptionAlgorithms()).containsExactly("A128CBC-HS256", "A128GCM");
		assertThat(providerConfiguration.getScopes()).containsExactly("openid", "email", "profile");
		assertThat(providerConfiguration.getClaimNames()).containsExactly("aud", "email", "exp", "iat", "iss", "name", "sub");
		assertThat(providerConfiguration.getCheckSessionIFrame().toString()).isEqualTo("https://example.com/oauth2/v3/check_session");
		assertThat(providerConfiguration.getEndSessionEndpoint().toString()).isEqualTo("https://example.com/oauth2/v3/end_session");
	}
}
