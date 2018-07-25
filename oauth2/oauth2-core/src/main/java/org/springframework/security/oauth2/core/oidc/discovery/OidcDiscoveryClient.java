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

/**
 * Implementations of this interface are responsible for obtaining
 * an OpenID Provider's configuration from it's Discovery Endpoint
 * using the issuer identifier.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OidcProviderConfiguration
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-session-1_0.html">OpenID Connect Session Management 1.0</a>
 */
public interface OidcDiscoveryClient {

	/**
	 * Returns the OpenID Provider's configuration from it's Discovery Endpoint
	 * using the provided issuer identifier.
	 *
	 * @param issuer the issuer identifier used to discover the Provider's configuration
	 * @return the {@link OidcProviderConfiguration}
	 */
	OidcProviderConfiguration discover(String issuer);

}
