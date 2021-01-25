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

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A factory for signing JWS payloads
 */
public class NimbusJwsSignerFactory implements JwsSignerFactory {

	private final JWKSource<SecurityContext> jwks;

	private Clock clock = Clock.systemUTC();

	private Consumer<Jwt.JwsSpec<?>> jwtCustomizer = (spec) -> {
	};

	/**
	 * Construct a {@link NimbusJwsSignerFactory} using the provided parameters
	 * @param jwks the source for looking up the appropriate signing JWK
	 */
	public NimbusJwsSignerFactory(JWKSource<SecurityContext> jwks) {
		this.jwks = jwks;
	}

	@Override
	public Jwt.JwsSpec<?> signer() {
		Instant now = Instant.now(this.clock);
		return new NimbusEncoderSpec(this.jwks).algorithm(SignatureAlgorithm.RS256).type("JWT")
				.jti(UUID.randomUUID().toString()).issuedAt(now).expiresAt(now.plusSeconds(3600))
				.apply(this.jwtCustomizer);
	}

	/**
	 * Set an application-level customizer for overriding claims and headers before
	 * signing.
	 * @param jwtCustomizer
	 */
	public void setJwtCustomizer(Consumer<Jwt.JwsSpec<?>> jwtCustomizer) {
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Set the {@link Clock} to use, mostly to simplify testing
	 * @param clock
	 */
	public void setClock(Clock clock) {
		this.clock = clock;
	}

	private static final class NimbusEncoderSpec extends Jwt.JwtSpecSupport<NimbusEncoderSpec>
			implements Jwt.JwsSpec<NimbusEncoderSpec> {

		private final JWKSource<SecurityContext> jwks;

		private NimbusEncoderSpec(JWKSource<SecurityContext> jwks) {
			this.jwks = jwks;
		}

		NimbusEncoderSpec apply(Consumer<Jwt.JwsSpec<?>> specConsumer) {
			specConsumer.accept(this);
			return this;
		}

		@Override
		public Jwt sign() {
			// consider using ConfigurableJWTMinter in Nimbus
			JWK jwk = jwk(this.headers);
			if (StringUtils.hasText(jwk.getKeyID())) {
				this.headers.put(JoseHeaderNames.KID, jwk.getKeyID());
			}
			if (jwk.getAlgorithm() != null) {
				this.headers.put(JoseHeaderNames.ALG, jwk.getAlgorithm().getName());
			}
			JWSHeader header = jwsHeader(this.headers);
			JWTClaimsSet claims = jwtClaimSet(this.claims);
			SignedJWT jwt = new SignedJWT(header, claims);
			sign(jwt, signer(jwk));
			Instant iat = toInstant(this.claims.get(JwtClaimNames.IAT));
			Instant exp = toInstant(this.claims.get(JwtClaimNames.EXP));
			String tokenValue = jwt.serialize();
			return new Jwt(tokenValue, iat, exp, this.headers, this.claims);
		}

		private JWK jwk(Map<String, Object> header) {
			try {
				JWSHeader jwsHeader = JWSHeader.parse(header);
				JWKSelector selector = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
				return CollectionUtils.firstElement(this.jwks.get(selector, null));
			}
			catch (Exception e) {
				throw new JwtException("Failed to lookup JWK", e);
			}
		}

		private JWSHeader jwsHeader(Map<String, Object> headers) {
			try {
				return JWSHeader.parse(headers);
			}
			catch (Exception e) {
				throw new JwtException("Failed to read JWS header", e);
			}
		}

		private JWTClaimsSet jwtClaimSet(Map<String, Object> claims) {
			Map<String, Object> datesConverted = new HashMap<>(claims);
			datesConverted.replaceAll((key, value) -> {
				if (value instanceof Instant) {
					return ((Instant) value).getEpochSecond();
				}
				return value;
			});
			try {
				return JWTClaimsSet.parse(datesConverted);
			}
			catch (Exception e) {
				throw new JwtException("Failed to read claims", e);
			}
		}

		private JWSSigner signer(JWK jwk) {
			try {
				return new DefaultJWSSignerFactory().createJWSSigner(jwk);
			}
			catch (Exception ex) {
				throw new JwtEncodingException("Failed to constructor signer", ex);
			}
		}

		private void sign(SignedJWT jwt, JWSSigner signer) {
			try {
				jwt.sign(signer);
			}
			catch (Exception e) {
				throw new JwtException("Failed to sign JWT", e);
			}
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp != null) {
				Assert.isInstanceOf(Instant.class, timestamp, "timestamps must be of type Instant");
			}
			return (Instant) timestamp;
		}

	}

}
