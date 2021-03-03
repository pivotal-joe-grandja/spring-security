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

import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenControllerOne {
	@Autowired
	JwtEncoder jwtEncoder;

	@Autowired
	Supplier<JoseHeader.Builder> defaultHeader;

	@Autowired
	Supplier<JwtClaimsSet.Builder> defaultClaimsSet;

	@GetMapping("/token/one")
	String tokenOne() {
		// Obtain application-scope defaults
		JoseHeader.Builder headersBuilder = this.defaultHeader.get();
		JwtClaimsSet.Builder claimsBuilder = this.defaultClaimsSet.get();

		// Apply request-scope headers/claims customization
		headersBuilder.headers((headers) -> headers.remove(JoseHeaderNames.CRIT));
		claimsBuilder.id("id");

		// Encode after headers/claims customization
		Jwt jwt = this.jwtEncoder.encode(headersBuilder.build(), claimsBuilder.build());

		return jwt.getTokenValue();
	}
}
