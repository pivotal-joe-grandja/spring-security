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

import java.util.Collections;

import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtBuilderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtBuilderFactory;
import org.springframework.security.oauth2.jwt.JwtSubjectApplier;
import org.springframework.security.oauth2.jwt.JwtTimestampApplier;

@Configuration
public class TokenConfigTwo {
	@Bean
	JwtBuilderFactory jwsBuilderFactory(RSAKey key) {
		NimbusJwtBuilderFactory<?> delegate = new NimbusJwtBuilderFactory<>();
		// JG:
		// 1) The NimbusJwtBuilderFactory has a null JWKSource,
		// 	which in turn uses the null JWKSource to create the NimbusJwtBuilder?
		// 2) This factory creates a new instance of NimbusJwtBuilder on each invocation?
		// 	Is this intended? NimbusJwtBuilder is a heavy-weight object - see notes in NimbusJwtBuilder
		return () -> delegate.create()
				.jwk(key) // simple to specify the key since I can expose Nimbus-specific methods when returning a builder
				// JG:
				// jwk() is implementation specific and not part of the core contract of JwtBuilderFactory
				// Also see the note in NimbusJwtBuilderFactory.NimbusJwtBuilder.jwk()
				.claimsSet((claims) -> claims.issuer("http://self"))
				.joseHeader((headers) -> headers.critical(Collections.singleton("exp"))) // application-level opinion that might need overriding
				.apply(new JwtTimestampApplier())
				.apply(new JwtSubjectApplier());
	}
}
