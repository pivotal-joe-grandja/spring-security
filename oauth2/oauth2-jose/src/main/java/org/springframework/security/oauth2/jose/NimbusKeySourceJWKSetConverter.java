/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jose;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.crypto.key.KeySource;
import org.springframework.util.Assert;

/**
 * A {@link Converter} that converts the provided {@link KeySource} to a
 * {@code com.nimbusds.jose.jwk.JWKSet}.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see KeySource
 * @see com.nimbusds.jose.jwk.JWKSet
 */
public final class NimbusKeySourceJWKSetConverter implements Converter<KeySource, JWKSet> {

	@Override
	public JWKSet convert(KeySource keySource) {
		Assert.notNull(keySource, "keySource cannot be null");

		// @formatter:off
		List<JWK> jwks = keySource.getKeyPairs().stream()
				.map(this::convert)
				.filter(Objects::nonNull)
				.collect(Collectors.toCollection(LinkedList::new));

		keySource.getSecretKeys().stream()
				.map(this::convert)
				.forEachOrdered(jwks::add);

		return new JWKSet(jwks);
		// @formatter:on
	}

	private JWK convert(KeyPair keyPair) {
		// @formatter:off
		if (keyPair.getPublic() instanceof RSAPublicKey) {
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			return new RSAKey.Builder(publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();
		}
		else if (keyPair.getPublic() instanceof ECPublicKey) {
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			return new ECKey.Builder(curve, publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();

		}
		return null;
		// @formatter:on
	}

	private JWK convert(SecretKey secretKey) {
		// @formatter:off
		return new OctetSequenceKey.Builder(secretKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

}
