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
public interface JwtEncoderAlternative {

	/**
	 * Return a signer that can be configured for signing payloads
	 * @return a configurable signer
	 */
	JwtPartial<?> signer();

	interface JwtPartial<B extends JwtPartial<B>> {
		B jwsHeaders(Consumer<Map<String, Object>> headersConsumer); // calling this jwsHeaders means we can add jweHeaders later, removing the ambiguity in the contract
		B claims(Consumer<Map<String, Object>> claimsConsumer);
		B jwsHeader(Consumer<JoseHeader.Builder> headerConsumer);
		B claimsSet(Consumer<JwtClaimsSet.Builder> claimsSetConsumer);
		Jwt sign();

		default B apply(Consumer<JwtPartial<?>> consumer) {
			consumer.accept(this);
			return (B) this;
		}
	}

	abstract class JwtPartialSupport<B extends JwtPartialSupport<B>> implements JwtPartial<B> {
		protected final JoseHeader.Builder headers = JoseHeader.builder();
		protected final JwtClaimsSet.Builder claims = JwtClaimsSet.builder();

		@Override
		public B jwsHeader(Consumer<JoseHeader.Builder> headersConsumer) {
			headersConsumer.accept(this.headers);
			return (B) this;
		}

		@Override
		public B claimsSet(Consumer<JwtClaimsSet.Builder> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return (B) this;
		}

		@Override
		public B jwsHeaders(Consumer<Map<String, Object>> headersConsumer) {
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
