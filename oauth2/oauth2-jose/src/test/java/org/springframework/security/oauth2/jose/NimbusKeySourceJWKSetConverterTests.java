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

package org.springframework.security.oauth2.jose;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.Test;

import org.springframework.security.crypto.key.KeySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link NimbusKeySourceJWKSetConverter}.
 *
 * @author Joe Grandja
 */
public class NimbusKeySourceJWKSetConverterTests {

	private NimbusKeySourceJWKSetConverter converter = new NimbusKeySourceJWKSetConverter();

	@Test
	public void convertWhenKeySourceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.convert(null))
				.withMessage("keySource cannot be null");
	}

	@Test
	public void convertWhenKeySourceProvidedThenConverted() {
		KeyPair rsaKeyPair = new KeyPair(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY);
		KeySource keySource = mock(KeySource.class);
		given(keySource.getKeyPairs())
				.willReturn(new LinkedHashSet<>(Arrays.asList(rsaKeyPair, TestKeys.DEFAULT_EC_KEY_PAIR)));
		given(keySource.getSecretKeys()).willReturn(Collections.singleton(TestKeys.DEFAULT_SECRET_KEY));

		JWKSet jwkSet = this.converter.convert(keySource);
		assertThat(jwkSet.getKeys()).hasSize(3);
		assertThat(jwkSet.getKeys()).extracting(JWK::getKeyType).containsExactly(KeyType.RSA, KeyType.EC, KeyType.OCT);
	}

}
