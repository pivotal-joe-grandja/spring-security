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

package sample.singlekey;

import java.time.Instant;
import java.util.Collections;
import java.util.function.Supplier;

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
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;

@Configuration
public class TokenConfigOne {
	@Bean
	public Supplier<JoseHeader.Builder> defaultHeader() {
		return () ->
			JoseHeader.builder()
					.algorithm(SignatureAlgorithm.RS256)
					.type("JWT")
					.critical(Collections.singleton("exp")); // application-level opinion that might need overriding
	}

	@Bean
	public Supplier<JwtClaimsSet.Builder> defaultClaimsSet() {
		return () -> {
			Instant now = Instant.now();
			return JwtClaimsSet.builder()
					.issuedAt(now)
					.expiresAt(now.plusSeconds(3600))
					.subject(SecurityContextHolder.getContext().getAuthentication().getName())
					.issuer("http://self");
		};
	}

	@Bean
	JwtEncoder jwtEncoder(RSAKey key) {
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(key));
		return new NimbusJwsEncoder(jwks);
	}
}
