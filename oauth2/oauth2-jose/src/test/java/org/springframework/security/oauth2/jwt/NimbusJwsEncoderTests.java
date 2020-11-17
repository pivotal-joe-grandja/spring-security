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

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwsEncoderTests {

	private RSAKey rsaJwk;

	private NimbusJwsEncoder jwsEncoder;

	@Before
	public void setUp() throws Exception {
		// @formatter:off
		this.rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("kid")
				.build();
		// @formatter:on
		this.jwsEncoder = new NimbusJwsEncoder(this.rsaJwk);
	}

	@Test
	public void constructorWhenJwkNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder(null))
				.withMessage("jwk cannot be null");
	}

	@Test
	public void constructorWhenJwkNotPrivateKeyThenThrowIllegalArgumentException() {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY).keyID("kid").build();
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder(rsaJwk))
				.withMessage("jwk must be a private/secret key");
	}

	@Test
	public void constructorWhenJwkKidNullThenThrowIllegalArgumentException() {
		RSAKey rsaJwk = new RSAKey.Builder(this.rsaJwk).keyID(null).build();
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder(rsaJwk))
				.withMessage("jwk.kid cannot be empty");
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
	public void encodeWhenSuccessThenDecodes() throws Exception {
		// @formatter:off
		JoseHeader joseHeader = TestJoseHeaders.joseHeader()
				.headers((headers) -> headers.remove(JoseHeaderNames.CRIT))
				.build();
		// @formatter:on
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwsEncoder.encode(joseHeader, jwtClaimsSet);

		// Assert headers/claims were added
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.TYP)).isEqualTo("JWT");
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(this.rsaJwk.getKeyID());
		assertThat(encodedJws.getId()).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(this.rsaJwk.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());
	}

}
