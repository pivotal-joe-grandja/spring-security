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

import java.util.Map;
import java.util.function.Consumer;

/**
 * A factory for signing JWS payloads
 */
public interface JwtBuilderFactory {

	/**
	 * Return a signer that can be configured for signing payloads
	 * @return a configurable signer
	 */
	JwtBuilder<?> create();

	/*
	 * JG:
	 * 1) This design does not allow the use of Lambda's since it's not a @FunctionalInterface.
	 * 	JwtEncoder.encode() allows the usage of Lambda's.
	 * 2) JwtBuilder.headers() and JwtBuilder.joseHeader() cannot be overloaded since the signature would be the same.
	 *	It's not ideal that the operation name needs to be different. This also applies for claims().
	 * 3) This builder is similar to Jwt.Builder. This will confuse user's.
	 * 	Which one should they use? Do we deprecate Jwt.Builder?
	 * 4) The only difference between JwtBuilder and JwtEncoder
	 * is that JwtBuilder provides customization hooks for headers and claims via the Consumer's.
	 * Alternatively, the headers and claims can be customized via JoseHeader.Builder and JwtClaimsSet.Builder
	 * and then passed into JwtEncoder for encoding ONLY. So customization happens BEFORE the encoding process.
	 * IMO, this makes the JwtEncoder API much simpler and defines the JoseHeader and JwtClaimsSet
	 * as first-class (JWT/JOSE) domain objects with their associated builders that allow for customization.
	 * 5) The JwtBuilderFactory API introduces 3 public API's: JwtBuilderFactory, JwtBuilder and JwtBuilderSupport.
	 * 	Whereas, JwtEncoder introduces 1 public API.
	 * 	NOTE: JoseHeader and JwtClaimsSet are shared by both API designs.
	 */
	interface JwtBuilder<B extends JwtBuilder<B>> {
		// calling this jwsHeaders means we can add jweHeaders later,
		// removing the ambiguity in the contract
		B headers(Consumer<Map<String, Object>> headersConsumer);

		// JG:
		// Consumer<Map<String, Object>> does not provide type-safety for headers or claims,
		// the preference is to use Consumer<JoseHeader.Builder> and Consumer<JwtClaimsSet.Builder>.
		// This also makes the API easier to use since the standard headers and claims are defined in the builders
		// and it also allows for custom headers and claims to be added.
		B claims(Consumer<Map<String, Object>> claimsConsumer);

		// JG:
		// In reply to above comment in headers(Consumer<Map<String, Object>>),
		// JoseHeader is designed to be used for Jwe as well,
		// e.g. JoseHeader.Builder.header() can be used to add ANY header - JWS, JWE or custom
		// I don't see any ambiguity in the contract
		B joseHeader(Consumer<JoseHeader.Builder> headersConsumer);

		B claimsSet(Consumer<JwtClaimsSet.Builder> claimsConsumer);

		// JG:
		// encode() used to be sign() before I renamed, however, both names are confusing since this is a Builder.
		// I would expect it to be build() instead.
		// Even if we kept it as sign(), then how do we handle JWE?
		// Logically, we would have encrypt() for JWE but this introduces a new operation.
		// Hence the generic name JwtEncoder.encode(), as it provides the flexibility
		// to handle both JWS or JWE based on the implementation.
		// I guess we could rename this to build() but I prefer encode()
		// as this is the "core operation" being performed.
		// It's encoding the headers and claims. It's not really building headers and claims.
		// This name also aligns with JwtDecoder.decode().
		Jwt encode();

		// JG:
		// I don't feel we need to introduce this.
		// The caller has access to the headers and claims via the Consumer operations.
		default B apply(Consumer<JwtBuilder<?>> builderConsumer) {
			builderConsumer.accept(this);
			return (B) this;
		}
	}

	abstract class JwtBuilderSupport<B extends JwtBuilderSupport<B>> implements JwtBuilder<B> {
		protected final JoseHeader.Builder headers = JoseHeader.builder();
		protected final JwtClaimsSet.Builder claims = JwtClaimsSet.builder();

		@Override
		public B joseHeader(Consumer<JoseHeader.Builder> headersConsumer) {
			headersConsumer.accept(this.headers);
			return (B) this;
		}

		@Override
		public B claimsSet(Consumer<JwtClaimsSet.Builder> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return (B) this;
		}

		@Override
		public B headers(Consumer<Map<String, Object>> headersConsumer) {
			this.headers.headers(headersConsumer);
			return (B) this;
		}

		@Override
		public B claims(Consumer<Map<String, Object>> claimsConsumer) {
			this.claims.claims(claimsConsumer);
			return (B) this;
		}
	}
}
