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
		return (headers, claims) -> {
			JoseHeader.Builder defaultHeaders = JoseHeader.from(headers);
			if (!headers.getHeaders().containsKey(JoseHeaderNames.CRIT)) { // can't tell if caller wants `crit` to not be in the header or wants to take the encoder's opinion
				defaultHeaders.critical(Collections.singleton("exp"));
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
