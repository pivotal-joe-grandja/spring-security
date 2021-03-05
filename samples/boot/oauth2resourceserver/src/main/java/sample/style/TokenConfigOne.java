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

package sample.style;

import java.time.Instant;
import java.util.Collections;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;

@Configuration
public class TokenConfigOne {
	@Bean
	JwtEncoder jwtEncoder(RSAKey key) {
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(key));
		NimbusJwsEncoder delegate = new NimbusJwsEncoder(jwks);

		// JG:
		// This lambda implementation of JwtEncoder is NOT actually a JwtEncoder type.
		// It does NOT perform encoding, which is the responsibility of the JwtEncoder, as documented in the API.
		// Instead, this lambda implementation performs headers and claims customization,
		// which IMO should be a separate concern that is handled by another component, e.g. jwtCustomizer.
		// I don't feel this is a valid sample and I would consider it an anti-pattern.
		return (headers, claims) -> {
			JoseHeader.Builder defaultHeaders = JoseHeader.from(headers);
			if (!headers.getHeaders().containsKey(JoseHeaderNames.CRIT)) { // can't tell if caller wants `crit` to not be in the header or wants to take the encoder's opinion
				// JG:
				// This does not make sense to me. Why is crit being added?
				// I'm not understanding the logic here.
				// The test tokenOneWhenDefaultsThenHasNoCritHeader() is invalid
				// as it expects crit to be null but this implementation adds it?
				// Therefore, I'm commenting out the below default so the test passes.
				// Also, I don't feel this is a valid implementation - see previous note.

				// defaultHeaders.critical(Collections.singleton("exp"));

				defaultHeaders.header("exp", Instant.now());
			}
			if (!headers.getHeaders().containsKey(JoseHeaderNames.TYP)) {
				defaultHeaders.type("JWT");
			}
			if (!headers.getHeaders().containsKey(JoseHeaderNames.ALG)) {
				defaultHeaders.algorithm(SignatureAlgorithm.RS256);
			}
			JwtClaimsSet.Builder defaultClaimsSet = JwtClaimsSet.from(claims);
			Instant now = Instant.now();
			if (!claims.hasClaim(JwtClaimNames.IAT)) {
				defaultClaimsSet.issuedAt(now);
			}
			if (!claims.hasClaim(JwtClaimNames.EXP)) {
				defaultClaimsSet.expiresAt(now.plusSeconds(3600));
			}
			if (!claims.hasClaim(JwtClaimNames.SUB)) {
				defaultClaimsSet.subject(SecurityContextHolder.getContext().getAuthentication().getName());
			}
			if (!claims.hasClaim(JwtClaimNames.ISS)) {
				defaultClaimsSet.issuer("http://self");
			}
			return delegate.encode(defaultHeaders.build(), defaultClaimsSet.build());
		};
	}
}
