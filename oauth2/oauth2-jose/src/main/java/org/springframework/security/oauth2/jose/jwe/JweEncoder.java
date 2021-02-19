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

package org.springframework.security.oauth2.jose.jwe;

import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

/**
 * @author Joe Grandja
 */
public interface JweEncoder extends JwtEncoder {

	/*
	 * The inherited operation:
	 *
	 * Jwt encode(JoseHeader headers, JwtClaimsSet claims)
	 *
	 * is meant to be used when encrypting a `JwtClaimsSet` as the payload.
	 *
	 * The new operation is meant to be used when encrypting a `String` as the payload.
	 * This can be used when nesting a JWS as the payload in a JWE.
	 *
	 * NOTE: The `String` type is quite limiting so this would need to change to some form
	 * of a wrapper (holder) object to allow for various data types,
	 * e.g. Map, String, byte[], Jwt, etc.
	 */
	Jwt encode(JoseHeader headers, String content) throws JwtEncodingException;

}
