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

package org.springframework.security.oauth2.jwt;

import java.util.Arrays;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwtEncoderAlternativeTests {

	private JWKSource<SecurityContext> jwkSelector;

	private NimbusJwtEncoderAlternative<SecurityContext> jwsEncoder;

	@Before
	public void setUp() {
		this.jwkSelector = mock(JWKSource.class);
		this.jwsEncoder = new NimbusJwtEncoderAlternative<>();
		this.jwsEncoder.setJwkSource(this.jwkSelector);
	}

	@Test
	public void constructorWhenJwkSelectorNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.setJwkSource(null))
				.withMessage("jwkSelector cannot be null");
	}

	@Test
	public void encodeWhenJwkNotSelectedThenThrowJwtEncodingException() {
		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.signer().sign())
				.withMessageContaining("Failed to select a JWK signing key");
	}

	@Test
	public void encodeWhenJwkUseEncryptionThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.signer().sign())
				.withMessageContaining(
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

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		Jwt encodedJws = this.jwsEncoder.signer().sign();

		// Assert headers/claims were added
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.TYP)).isEqualTo("JWT");
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJws.getId()).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());
	}

	@Test
	public void encodeWhenCustomizerSetThenCalled() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		Consumer<JwtEncoderAlternative.JwtPartial<?>> jwtCustomizer = mock(Consumer.class);
		JwtEncoderAlternative encoder = () -> this.jwsEncoder.signer().apply(jwtCustomizer);
		encoder.signer().sign();

		verify(jwtCustomizer).accept(any(JwtEncoderAlternative.JwtPartial.class));
	}

	@Test
	public void defaultJwkSelectorApplyWhenMultipleSelectedThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk, rsaJwk));

		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.signer().sign())
				.withMessageContaining("Found multiple JWK signing keys for algorithm 'RS256'");
	}

	@Test
	public void encodeWhenKeysRotatedThenNewKeyUsed() throws Exception {
		// @formatter:off
		RSAKey first = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("first")
				.build();
		RSAKey second = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("second")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(first));

		Jwt encodedJws = this.jwsEncoder.signer().sign();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey((first).toRSAPublicKey()).build();
		Jwt firstDecoded = jwtDecoder.decode(encodedJws.getTokenValue());

		reset(this.jwkSelector);
		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(second));

		encodedJws = this.jwsEncoder.signer().sign();

		jwtDecoder = NimbusJwtDecoder.withPublicKey((second).toRSAPublicKey()).build();
		Jwt secondDecoded = jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(firstDecoded.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(first.getKeyID());
		assertThat(secondDecoded.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(second.getKeyID());
	}

	@Test
	public void encodeWhenClaimsThenContains() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		Jwt encodedJws = this.jwsEncoder.signer()
				.claimsSet((claims) -> claims.subject("subject")).sign();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt decoded = jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(decoded.getSubject()).isEqualTo("subject");
	}

	@Test
	public void encodeWhenDefaultClaimRemovedThenRemoved() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		Jwt encodedJws = this.jwsEncoder.signer()
				.claims((claims) -> claims.remove("exp"))
				.claimsSet((claims) -> claims.subject("subject")).sign();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt decoded = jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(decoded.getExpiresAt()).isNull();
	}

}
