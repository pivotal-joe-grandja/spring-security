/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;

import org.springframework.security.oauth2.jose.NimbusKeySourceJWKSetConverter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.util.Assert;

/**
 * A {@link JwtEncoderFactory factory} that provides a {@link JwtEncoder} supporting JSON
 * Web Signature (JWS).
 *
 * @author Joe Grandja
 * @since 5.5
 * @see JwtEncoderFactory
 * @see JoseHeader
 * @see NimbusJwsEncoder
 * @see NimbusKeySourceJWKSetConverter
 * @see com.nimbusds.jose.jwk.JWKSet
 */
public final class NimbusJwsEncoderFactory implements JwtEncoderFactory<JoseHeader> {

	private static final String ENCODER_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to create a JwtEncoder: %s";

	private final Map<JwsAlgorithm, JwtEncoder> jwsEncoders = new ConcurrentHashMap<>();

	private final Supplier<JWKSet> jwkSetProvider;

	private final JWKSource<?> jwkSource;

	/**
	 * Constructs a {@code NimbusJwsEncoderFactory} using the provided parameters.
	 * @param jwkSetProvider a {@code Supplier} of {@code com.nimbusds.jose.jwk.JWKSet}
	 */
	public NimbusJwsEncoderFactory(Supplier<JWKSet> jwkSetProvider) {
		Assert.notNull(jwkSetProvider, "jwkSetProvider cannot be null");
		this.jwkSetProvider = jwkSetProvider;
		this.jwkSource = (jwkSelector, context) -> jwkSelector.select(this.jwkSetProvider.get());
	}

	@Override
	public JwtEncoder createEncoder(JoseHeader header) {
		Assert.notNull(header, "header cannot be null");
		return this.jwsEncoders.computeIfAbsent(header.getAlgorithm(), this::buildEncoder);
	}

	private JwtEncoder buildEncoder(JwsAlgorithm jwsAlgorithm) {
		try {
			JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwsAlgorithm.getName());
			JWSHeader jwsHeader = new JWSHeader(jwsAlg);
			JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
			List<JWK> jwks = this.jwkSource.get(jwkSelector, null);

			if (jwks.isEmpty()) {
				throw new IllegalStateException(String.format(ENCODER_ERROR_MESSAGE_TEMPLATE,
						"Unable to find signing key for algorithm '" + jwsAlgorithm.getName() + "'"));
			}
			else if (jwks.size() > 1) {
				throw new IllegalStateException(String.format(ENCODER_ERROR_MESSAGE_TEMPLATE,
						"Found multiple signing keys for algorithm '" + jwsAlgorithm.getName() + "'"));
			}

			return new NimbusJwsEncoder(jwks.get(0));

		}
		catch (JOSEException ex) {
			throw new IllegalStateException(String.format(ENCODER_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

}
