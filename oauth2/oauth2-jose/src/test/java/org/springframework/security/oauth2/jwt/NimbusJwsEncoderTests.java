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

import java.security.KeyPair;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.crypto.key.KeySource;
import org.springframework.security.oauth2.jose.NimbusKeySourceJWKSetConverter;
import org.springframework.security.oauth2.jose.TestKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwsEncoderTests {

	private Function<JoseHeader, JWK> jwkSelector;

	private NimbusJwsEncoder jwsEncoder;

	@Before
	public void setUp() {
		this.jwkSelector = mock(Function.class);
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSelector);
	}

	@Test
	public void constructorWhenJwkSelectorNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder(null))
				.withMessage("jwkSelector cannot be null");
	}

	@Test
	public void encodeWhenHeadersNullThenThrowIllegalArgumentException() {
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.encode(null, jwtClaimsSet))
				.withMessage("headers cannot be null");
	}

	@Test
	public void encodeWhenClaimsNullThenThrowIllegalArgumentException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();

		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.encode(joseHeader, null))
				.withMessage("claims cannot be null");
	}

	@Test
	public void encodeWhenJwkNotSelectedThenThrowJwtEncodingException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("Failed to select a JWK signing key");
	}

	@Test
	public void encodeWhenJwkKidNullThenThrowJwtEncodingException() {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.build();
		// @formatter:on

		given(this.jwkSelector.apply(any())).willReturn(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("The \"kid\" (key ID) from the selected JWK cannot be empty");
	}

	@Test
	public void encodeWhenJwkUseEncryptionThenThrowJwtEncodingException() {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		// @formatter:on

		given(this.jwkSelector.apply(any())).willReturn(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet)).withMessageContaining(
						"Failed to create a JWS Signer -> The JWK use must be sig (signature) or unspecified");
	}

	@Test
	public void encodeWhenSuccessThenDecodes() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.apply(any())).willReturn(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwsEncoder.encode(joseHeader, jwtClaimsSet);

		// Assert headers/claims were added
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.TYP)).isEqualTo("JWT");
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJws.getId()).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());
	}

	@Test
	public void defaultJwkSelectorConstructorWhenJwkSetProviderNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder.DefaultJwkSelector(null))
				.withMessage("jwkSetProvider cannot be null");
	}

	@Test
	public void defaultJwkSelectorApplyWhenHeadersNullThenThrowIllegalArgumentException() {
		Supplier<JWKSet> jwkSetProvider = mock(Supplier.class);
		NimbusJwsEncoder.DefaultJwkSelector jwkSelector = new NimbusJwsEncoder.DefaultJwkSelector(jwkSetProvider);

		assertThatIllegalArgumentException().isThrownBy(() -> jwkSelector.apply(null))
				.withMessageContaining("headers cannot be null");
	}

	@Test
	public void defaultJwkSelectorApplyWhenMultipleSelectedThenThrowJwtEncodingException() {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		Supplier<JWKSet> jwkSetProvider = mock(Supplier.class);
		given(jwkSetProvider.get()).willReturn(new JWKSet(Arrays.asList(rsaJwk, rsaJwk)));
		NimbusJwsEncoder.DefaultJwkSelector jwkSelector = new NimbusJwsEncoder.DefaultJwkSelector(jwkSetProvider);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();

		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> jwkSelector.apply(joseHeader))
				.withMessageContaining("Found multiple JWK signing keys for algorithm 'RS256'");
	}

	@Test
	public void encodeWhenKeysRotatedThenNewKeyUsed() throws Exception {
		TestJwkSetProvider jwkSetProvider = new TestJwkSetProvider(new TestKeySource());
		Function<JoseHeader, JWK> jwkSelector = new NimbusJwsEncoder.DefaultJwkSelector(jwkSetProvider);
		Function<JoseHeader, JWK> jwkSelectorDelegate = spy(new Function<JoseHeader, JWK>() {
			@Override
			public JWK apply(JoseHeader headers) {
				return jwkSelector.apply(headers);
			}
		});

		JwkResultCaptor jwkResultCaptor = new JwkResultCaptor();
		willAnswer(jwkResultCaptor).given(jwkSelectorDelegate).apply(any());

		NimbusJwsEncoder jwsEncoder = new NimbusJwsEncoder(jwkSelectorDelegate);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = jwsEncoder.encode(joseHeader, jwtClaimsSet);

		JWK jwk1 = jwkResultCaptor.getResult();
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk1).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		jwkSetProvider.rotate(); // Trigger key rotation

		encodedJws = jwsEncoder.encode(joseHeader, jwtClaimsSet);

		JWK jwk2 = jwkResultCaptor.getResult();
		jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk2).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(jwk1.getKeyID()).isNotEqualTo(jwk2.getKeyID());
	}

	private static final class JwkResultCaptor implements Answer<JWK> {

		private JWK result;

		private JWK getResult() {
			return this.result;
		}

		@SuppressWarnings("unchecked")
		@Override
		public JWK answer(InvocationOnMock invocationOnMock) throws Throwable {
			this.result = (JWK) invocationOnMock.callRealMethod();
			return this.result;
		}

	}

	private static final class TestJwkSetProvider implements Supplier<JWKSet> {

		private final Converter<KeySource, JWKSet> jwkSetConverter = new NimbusKeySourceJWKSetConverter();

		private final KeySource keySource;

		private JWKSet jwkSet;

		private TestJwkSetProvider(KeySource keySource) {
			this.keySource = keySource;
			init();
		}

		@Override
		public JWKSet get() {
			return this.jwkSet;
		}

		private void init() {
			this.jwkSet = this.jwkSetConverter.convert(this.keySource);
		}

		private void rotate() {
			// ** Assumption **
			// this.keySource (TestKeySource) is a basic implementation
			// that holds the keys statically. However, let's make the assumption
			// that the keys are dynamically updated based on the implementation
			// requirements.
			// Therefore, getKeyPairs() and getSecretKeys() will always return the
			// "active" keys.
			init();
		}

	}

	private static final class TestKeySource implements KeySource {

		private final Set<KeyPair> keyPairs;

		private final Set<SecretKey> secretKeys;

		private TestKeySource() {
			this.keyPairs = new LinkedHashSet<>();
			this.keyPairs.add(TestKeys.DEFAULT_RSA_KEY_PAIR);
			this.keyPairs.add(TestKeys.DEFAULT_EC_KEY_PAIR);
			this.secretKeys = new LinkedHashSet<>();
			this.secretKeys.add(TestKeys.DEFAULT_SECRET_KEY);
		}

		@Override
		public Set<KeyPair> getKeyPairs() {
			return this.keyPairs;
		}

		@Override
		public Set<SecretKey> getSecretKeys() {
			return this.secretKeys;
		}

	}

}
