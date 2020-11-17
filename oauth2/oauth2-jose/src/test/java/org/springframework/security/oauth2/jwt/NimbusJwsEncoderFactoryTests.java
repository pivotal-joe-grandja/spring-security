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

import java.util.Arrays;
import java.util.function.Supplier;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link NimbusJwsEncoderFactory}.
 *
 * @author Joe Grandja
 */
public class NimbusJwsEncoderFactoryTests {

	private RSAKey rsaJwk;

	private Supplier<JWKSet> jwkSetProvider;

	private NimbusJwsEncoderFactory jwsEncoderFactory;

	@Before
	public void setUp() {
		// @formatter:off
		this.rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("kid")
				.build();
		// @formatter:on
		this.jwkSetProvider = mock(Supplier.class);
		given(this.jwkSetProvider.get()).willReturn(new JWKSet(this.rsaJwk));
		this.jwsEncoderFactory = new NimbusJwsEncoderFactory(this.jwkSetProvider);
	}

	@Test
	public void constructorWhenJwkSetProviderNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoderFactory(null))
				.withMessage("jwkSetProvider cannot be null");
	}

	@Test
	public void createEncoderWhenHeaderNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoderFactory.createEncoder(null))
				.withMessage("header cannot be null");
	}

	@Test
	public void createEncoderWhenKeyNotFoundThenThrowIllegalStateException() {
		assertThatIllegalStateException().isThrownBy(
				() -> this.jwsEncoderFactory.createEncoder(JoseHeader.withAlgorithm(SignatureAlgorithm.ES256).build()))
				.withMessageContaining("Unable to find signing key for algorithm 'ES256'");
	}

	@Test
	public void createEncoderWhenMultipleKeysFoundThenThrowIllegalStateException() {
		given(this.jwkSetProvider.get()).willReturn(new JWKSet(Arrays.asList(this.rsaJwk, this.rsaJwk)));
		assertThatIllegalStateException().isThrownBy(
				() -> this.jwsEncoderFactory.createEncoder(JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build()))
				.withMessageContaining("Found multiple signing keys for algorithm 'RS256'");
	}

	@Test
	public void createEncoderWhenKeyFoundThenReturnEncoder() {
		assertThat(this.jwsEncoderFactory.createEncoder(JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build()))
				.isNotNull();
	}

}
