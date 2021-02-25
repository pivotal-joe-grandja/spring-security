/*
 * Copyright 2002-2018 the original author or authors.
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author Josh Cummings
 */
@SpringBootApplication
public class SecurityContextApplication {

	@Bean
	UserDetailsService users() {
		return new InMemoryUserDetailsManager(User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.authorities("app")
				.build());
	}

	@Bean
	RSAKey key() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = generator.generateKeyPair();
		RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(pub).privateKey(priv).keyIDFromThumbprint().build();
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurityContextApplication.class, args);
	}
}
