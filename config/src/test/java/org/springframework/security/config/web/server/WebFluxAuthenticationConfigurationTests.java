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

package org.springframework.security.config.web.server;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;

/**
 * @author Joe Grandja
 */
public class WebFluxAuthenticationConfigurationTests {

	// @formatter:off
	private static final ClientRegistration GOOGLE_REGISTRATION = CommonOAuth2Provider.GOOGLE.getBuilder("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.build();
	// @formatter:on

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	private WebTestClient webClient;

	@Autowired
	public void setup(ApplicationContext context) {
		// @formatter:off
		this.webClient = WebTestClient
				.bindToApplicationContext(context)
				.build();
		// @formatter:on
	}

	@Test
	public void httpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() {
		this.spring.register(HttpBasicConfig.class, WebFluxConfig.class).autowire();

		// @formatter:off
		this.webClient.get()
				.uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().isUnauthorized();
		// @formatter:on
	}

	@Test
	public void formLogin_requestWhenXHRNotAuthenticatedThenRedirectToLogin() {
		this.spring.register(FormLoginConfig.class, WebFluxConfig.class).autowire();

		// @formatter:off
		this.webClient.get()
				.uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueEquals(HttpHeaders.LOCATION, "/login");
		// @formatter:on
	}

	@Test
	public void formLoginHttpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() {
		this.spring.register(FormLoginHttpBasicConfig.class, WebFluxConfig.class).autowire();

		// @formatter:off
		this.webClient.get()
				.uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().isUnauthorized();
		// @formatter:on
	}

	@Test
	public void oauth2Login_requestWhenXHRNotAuthenticatedThenRedirectToLogin() {
		this.spring.register(OAuth2LoginConfig.class, WebFluxConfig.class).autowire();

		// @formatter:off
		this.webClient.get()
				.uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueEquals(HttpHeaders.LOCATION, "/login");
		// @formatter:on
	}

	@Test
	public void oauth2LoginHttpBasic_requestWhenXHRNotAuthenticatedThenUnauthorized() {
		this.spring.register(OAuth2LoginHttpBasicConfig.class, WebFluxConfig.class).autowire();

		// @formatter:off
		this.webClient.get()
				.uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().isUnauthorized();
		// @formatter:on
	}

	@EnableWebFlux
	static class WebFluxConfig {

	}

	@EnableWebFluxSecurity
	static class HttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			return http
					.authorizeExchange((authorizeExchange) ->
							authorizeExchange
									.anyExchange().authenticated()
					)
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			ReactiveUserDetailsService userDetailsService = ReactiveAuthenticationTestConfiguration
					.userDetailsService();
			return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
		}

	}

	@EnableWebFluxSecurity
	static class FormLoginConfig {

		// @formatter:off
		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			return http
					.authorizeExchange((authorizeExchange) ->
							authorizeExchange
									.anyExchange().authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			ReactiveUserDetailsService userDetailsService = ReactiveAuthenticationTestConfiguration
					.userDetailsService();
			return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
		}

	}

	@EnableWebFluxSecurity
	static class FormLoginHttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			return http
					.authorizeExchange((authorizeExchange) ->
							authorizeExchange
									.anyExchange().authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			ReactiveUserDetailsService userDetailsService = ReactiveAuthenticationTestConfiguration
					.userDetailsService();
			return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
		}

	}

	@EnableWebFluxSecurity
	static class OAuth2LoginConfig {

		// @formatter:off
		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			return http
					.authorizeExchange((authorizeExchange) ->
							authorizeExchange
									.anyExchange().authenticated()
					)
					.oauth2Login(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(GOOGLE_REGISTRATION);
		}

	}

	@EnableWebFluxSecurity
	static class OAuth2LoginHttpBasicConfig {

		// @formatter:off
		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			return http
					.authorizeExchange((authorizeExchange) ->
							authorizeExchange
									.anyExchange().authenticated()
					)
					.oauth2Login(Customizer.withDefaults())
					.httpBasic(Customizer.withDefaults())
					.build();
		}
		// @formatter:on

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(GOOGLE_REGISTRATION);
		}

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			ReactiveUserDetailsService userDetailsService = ReactiveAuthenticationTestConfiguration
					.userDetailsService();
			return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
		}

	}

}
