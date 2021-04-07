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

package org.springframework.security.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Joe Grandja
 */
public class AuthenticationConfigurationTests {

	// @formatter:off
	private static final ClientRegistration GOOGLE_REGISTRATION = CommonOAuth2Provider.GOOGLE.getBuilder("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.build();
	// @formatter:on

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Test
	public void httpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(HttpBasicConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/")
				.header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void formLogin_requestWhenXHRNotAuthenticatedThenRedirectToLogin() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/")
				.header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void formLoginHttpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(FormLoginHttpBasicConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/")
				.header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void oauth2Login_requestWhenXHRNotAuthenticatedThenRedirectToLogin() throws Exception {
		this.spring.register(OAuth2LoginConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/")
				.header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void oauth2LoginHttpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(OAuth2LoginHttpBasicConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/")
				.header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@EnableWebSecurity
	static class HttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http
					.authorizeRequests((authorizeRequests) ->
							authorizeRequests
									.anyRequest().authenticated()
					)
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	static class FormLoginConfig {

		// @formatter:off
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http
					.authorizeRequests((authorizeRequests) ->
							authorizeRequests
									.anyRequest().authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	static class FormLoginHttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http
					.authorizeRequests((authorizeRequests) ->
							authorizeRequests
									.anyRequest().authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	static class OAuth2LoginConfig {

		// @formatter:off
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http
					.authorizeRequests((authorizeRequests) ->
							authorizeRequests
									.anyRequest().authenticated()
					)
					.oauth2Login((oauth2Login) ->
							oauth2Login
									.clientRegistrationRepository(clientRegistrationRepository()))
					.build();
		}
		// @formatter:on

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(GOOGLE_REGISTRATION);
		}

	}

	@EnableWebSecurity
	static class OAuth2LoginHttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http
					.authorizeRequests((authorizeRequests) ->
							authorizeRequests
									.anyRequest().authenticated()
					)
					.oauth2Login((oauth2Login) ->
							oauth2Login
									.clientRegistrationRepository(clientRegistrationRepository()))
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(GOOGLE_REGISTRATION);
		}

	}

}
