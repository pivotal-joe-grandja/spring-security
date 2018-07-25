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

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

/**
 * The default implementation of an {@link OidcDiscoveryClient}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OidcDiscoveryClient
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
public class DefaultOidcDiscoveryClient implements OidcDiscoveryClient {
	private static final String WELL_KNOWN_CONFIGURATION_URI = "/.well-known/openid-configuration";
	private final RestOperations restClient = new RestTemplate();

	@Override
	public OidcProviderConfiguration discover(String issuer) {
		Assert.hasText(issuer, "issuer cannot be empty");

		URI uri = UriComponentsBuilder.fromUriString(issuer)
				.path(WELL_KNOWN_CONFIGURATION_URI)
				.build()
				.toUri();
		RequestEntity<Void> request = RequestEntity.get(uri)
				.accept(MediaType.APPLICATION_JSON)
				.build();

		ParameterizedTypeReference<Map<String, Object>> typeReference =
				new ParameterizedTypeReference<Map<String, Object>>() {};

		ResponseEntity<Map<String, Object>>	response =
				this.restClient.exchange(request, typeReference);

		if (response.getStatusCodeValue() != 200) {
			String message = "The OpenID Provider Configuration Response did not return a 200 status -> returned " +
					response.getStatusCodeValue();
			throw new RestClientResponseException(
					message, response.getStatusCodeValue(), message, null, null, null);
		}

		OidcProviderConfiguration providerConfiguration = new OidcProviderConfiguration(response.getBody());

		String issuerClaim = providerConfiguration.getIssuer().toString();
		if (!issuerClaim.equals(issuer)) {
			throw new IllegalStateException("The issuer \"" + issuerClaim + "\" in the OpenID Provider Configuration" +
					" did not match the requested issuer \"" + issuer + "\".");
		}

		return providerConfiguration;
	}
}
