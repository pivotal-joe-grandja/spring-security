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

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SingleKeyApplicationTests {
	@Autowired
	MockMvc mvc;

	@Autowired
	RSAKey key;

	JwtDecoder jwtDecoder;

	@Before
	public void setup() throws Exception {
		this.jwtDecoder = NimbusJwtDecoder.withPublicKey(this.key.toRSAPublicKey()).build();
	}

	@Test
	@WithMockUser
	public void tokenOneWhenDefaultsThenHasNoCritHeader() throws Exception {
		String token = this.mvc.perform(get("/token/one")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getHeaders().get(JoseHeaderNames.CRIT)).isNull();
	}

	@Test
	@WithMockUser
	public void tokenOneWhenDefaultsThenHasDefaultIssuer() throws Exception {
		String token = this.mvc.perform(get("/token/one")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getIssuer().toExternalForm()).isEqualTo("http://self");
	}

	@Test
	@WithMockUser
	public void tokenOneWhenDefaultsThenHasCustomId() throws Exception {
		String token = this.mvc.perform(get("/token/one")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getId()).isEqualTo("id");
	}

	@Test
	@WithMockUser
	public void tokenOneWhenDefaultsThenHasNoKid() throws Exception {
		String token = this.mvc.perform(get("/token/one")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getHeaders().get(JoseHeaderNames.KID)).isNull();
	}

	@Test
	@WithMockUser
	public void tokenTwoWhenDefaultsThenHasNoCritHeader() throws Exception {
		String token = this.mvc.perform(get("/token/two")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getHeaders().get(JoseHeaderNames.CRIT)).isNull();
	}

	@Test
	@WithMockUser
	public void tokenTwoWhenDefaultsThenHasDefaultIssuer() throws Exception {
		String token = this.mvc.perform(get("/token/two")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getIssuer().toExternalForm()).isEqualTo("http://self");
	}

	@Test
	@WithMockUser
	public void tokenTwoWhenDefaultsThenHasCustomId() throws Exception {
		String token = this.mvc.perform(get("/token/two")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getId()).isEqualTo("id");
	}

	@Test
	@WithMockUser
	public void tokenTwoWhenDefaultsThenHasNoKid() throws Exception {
		String token = this.mvc.perform(get("/token/two")).andReturn().getResponse().getContentAsString();
		Jwt jwt = this.jwtDecoder.decode(token);
		assertThat(jwt.getHeaders().get(JoseHeaderNames.KID)).isNull();
	}
}
