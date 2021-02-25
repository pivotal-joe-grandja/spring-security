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

package sample.context;

import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.JwtEncoderAlternative.JwtPartial;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoderAlternative;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenControllerTwo {
	@Autowired
	NimbusJwtEncoderAlternative<TenantSecurityContext> jwsEncoder;

	@Autowired
	Consumer<JwtPartial<?>> jwsCustomizer;

	@GetMapping("/token/two")
	String tokenTwo() {
		return this.jwsEncoder.signer()
				.apply(this.jwsCustomizer)
				.claimsSet((claims) -> claims.id("id"))
				.jwsHeaders((headers) -> headers.remove(JoseHeaderNames.CRIT))
				.securityContext(new TenantSecurityContext("subdomain"))
				.sign().getTokenValue();
	}
}
