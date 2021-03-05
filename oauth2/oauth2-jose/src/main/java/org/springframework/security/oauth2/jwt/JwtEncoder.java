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

import org.springframework.util.Assert;

/**
 * Implementations of this interface are responsible for encoding a JSON Web Token (JWT)
 * to it's compact claims representation format.
 *
 * <p>
 * JWTs may be represented using the JWS Compact Serialization format for a JSON Web
 * Signature (JWS) structure or JWE Compact Serialization format for a JSON Web Encryption
 * (JWE) structure. Therefore, implementors are responsible for signing a JWS and/or
 * encrypting a JWE.
 *
 * @author Anoop Garlapati
 * @author Joe Grandja
 * @since 5.5
 * @see Jwt
 * @see JoseHeader
 * @see JwtClaimsSet
 * @see JwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption
 * (JWE)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS
 * Compact Serialization</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-3.1">JWE
 * Compact Serialization</a>
 */
@FunctionalInterface
public interface JwtEncoder {

	/**
	 * Encode the JWT to it's compact claims representation format.
	 * @param headers the JOSE header
	 * @param claims the JWT Claims Set
	 * @return a {@link Jwt}
	 * @throws JwtEncodingException if an error occurs while attempting to encode the JWT
	 */
	default Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtEncodingException {
		return encode(headers, new Payload<>(claims));
	}

	/*
	 * This new operation demonstrates how we can grow the API
	 * to support a payload with different data type(s).
	 *
	 * NOTE:
	 * This DOES NOT break the existing contract,
	 * and simply shows how we can grow it to support this feature at a later point (when needed).
	 *
	 * One example, that we'll likely need to support is the "Nested JWS in JWE" use case.
	 * See test -> NimbusJweEncoderTests.encodeWhenPayloadNestedJwsThenEncodes()
	 *
	 * The primary advantage for using the `Payload` (wrapper) type
	 * is that it provides us the greatest flexibility to sign/encrypt ANY data type,
	 * whether it's a JwtClaimsSet, String, byte[], Jwt, etc.
	 */
	Jwt encode(JoseHeader headers, Payload<?> payload) throws JwtEncodingException;

	/*
	 * NOTE:
	 * Payload is defined here just to demonstrate
	 * but it may be extracted into it's own (outer) class.
	 */
	class Payload<T> {
		T content;

		public Payload(T content) {
			Assert.notNull(content, "content cannot be null");
			this.content = content;
		}

		public T getContent() {
			return content;
		}
	}
}
