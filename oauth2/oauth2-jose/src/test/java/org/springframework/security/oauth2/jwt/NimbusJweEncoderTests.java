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

import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jwe.JweAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link NimbusJweEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJweEncoderTests {

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwsEncoder jwsEncoder;

	private NimbusJweEncoder jweEncoder;

	@Before
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSource);
		this.jweEncoder = new NimbusJweEncoder(this.jwkSource);
	}

	@Test
	public void encodeWhenPayloadJwtClaimsSetThenEncodes() {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JoseHeader jweHeader = JoseHeader.withAlgorithm(JweAlgorithm.RSA_OAEP_256)
				.header("enc", EncryptionMethod.A256GCM.getName())
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJwe = this.jweEncoder.encode(jweHeader, jwtClaimsSet);

		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(JweAlgorithm.RSA_OAEP_256);
		assertThat(encodedJwe.getHeaders().get("enc")).isEqualTo(EncryptionMethod.A256GCM.getName());
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJwe.getTokenValue()).isNotNull();
	}

	@Test
	public void encodeWhenPayloadNestedJwsThenEncodes() {
		// NOTE:
		// See Nimbus example -> Nested signed and encrypted JWT
		// https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt

		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JoseHeader jwsHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwsEncoder.encode(jwsHeader, jwtClaimsSet);

		JoseHeader jweHeader = JoseHeader.withAlgorithm(JweAlgorithm.RSA_OAEP_256)
				.header("enc", EncryptionMethod.A256GCM.getName())
				.contentType("JWT")
				.build();

		Jwt encodedJweNestedJws = this.jweEncoder.encode(
				jweHeader, new JwtEncoder.Payload<>(encodedJws.getTokenValue()));

		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(JweAlgorithm.RSA_OAEP_256);
		assertThat(encodedJweNestedJws.getHeaders().get("enc")).isEqualTo(EncryptionMethod.A256GCM.getName());
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.CTY)).isEqualTo("JWT");
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJweNestedJws.getTokenValue()).isNotNull();
	}

}
