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

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A representation of an OpenID Provider Configuration Response,
 * which is returned from an Issuer's Discovery Endpoint,
 * and contains a set of claims about the OpenID Provider's configuration.
 * The claims are defined by the OpenID Connect Discovery 1.0 and
 * OpenID Connect Session Management 1.0 specifications.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OidcProviderMetadataClaimAccessor
 * @see OidcDiscoveryClient
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">OpenID Provider Configuration Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-session-1_0.html#OPMetadata">OpenID Connect Session Management 1.0</a>
 */
public class OidcProviderConfiguration implements OidcProviderMetadataClaimAccessor {
	private final Map<String, Object> claims;

	/**
	 * Constructs an {@code OidcProviderConfiguration} using the provided parameters.
	 *
	 * @param claims the claims about the OpenID Provider's configuration
	 */
	public OidcProviderConfiguration(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}
}
