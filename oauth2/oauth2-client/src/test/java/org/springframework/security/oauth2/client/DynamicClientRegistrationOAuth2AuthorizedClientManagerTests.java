/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Joe Grandja
 */
public class DynamicClientRegistrationOAuth2AuthorizedClientManagerTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2AuthorizedClientProvider authorizedClientProvider;
	private Function contextAttributesMapper;
	private DynamicClientRegistrationOAuth2AuthorizedClientManager authorizedClientManager;
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;
	private ArgumentCaptor<OAuth2AuthorizationContext> authorizationContextCaptor;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientService = new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository);
		this.authorizedClientProvider = mock(OAuth2AuthorizedClientProvider.class);
		this.contextAttributesMapper = mock(Function.class);
		this.authorizedClientManager = new DynamicClientRegistrationOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientService);
		this.authorizedClientManager.setAuthorizedClientProvider(this.authorizedClientProvider);
		this.authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
		this.authorizationContextCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationContext.class);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderAndScopeOverrideThenAuthorized() {
		Set<String> scopeOverride = new HashSet<>(Arrays.asList("scope1", "scope2"));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.attribute(DynamicClientRegistrationOAuth2AuthorizedClientManager.SCOPES_ATTRIBUTE_NAME, scopeOverride)
				.principal(this.principal)
				.build();

		ClientRegistration mergedClientRegistration = DynamicClientRegistrationOAuth2AuthorizedClientManager.mergeClientRegistrationOverridesIfNecessary(
				this.clientRegistration, authorizeRequest);

		this.authorizedClient = new OAuth2AuthorizedClient(
				mergedClientRegistration, this.authorizedClient.getPrincipalName(),
				this.authorizedClient.getAccessToken(), this.authorizedClient.getRefreshToken());

		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(this.authorizedClient);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualToIgnoringGivenFields(mergedClientRegistration, "providerDetails");		// ClientRegistration.toString() needs to be updated for providerDetails
		assertThat(authorizationContext.getClientRegistration().getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);

		// Make sure it can be re-loaded
		OAuth2AuthorizedClient existingAuthorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		verify(this.authorizedClientProvider, times(2)).authorize(this.authorizationContextCaptor.capture());
		authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getAuthorizedClient()).isNotNull();
		assertThat(authorizationContext.getAuthorizedClient()).isEqualTo(existingAuthorizedClient);
	}
}
