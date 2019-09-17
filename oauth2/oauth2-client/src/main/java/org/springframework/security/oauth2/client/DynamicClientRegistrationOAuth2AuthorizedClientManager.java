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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * An implementation of an {@link OAuth2AuthorizedClientManager}
 * that is capable of operating outside of a {@code HttpServletRequest} context,
 * e.g. in a scheduled/background thread and/or in the service-tier.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientManager
 * @see OAuth2AuthorizedClientProvider
 * @see OAuth2AuthorizedClientService
 */
public final class DynamicClientRegistrationOAuth2AuthorizedClientManager implements OAuth2AuthorizedClientManager {
	public final static String SCOPES_ATTRIBUTE_NAME = ClientRegistration.class.getName().concat(".SCOPES");
	public final static String AUTHORIZATION_GRANT_TYPE_ATTRIBUTE_NAME = ClientRegistration.class.getName().concat(".AUTHORIZATION_GRANT_TYPE");
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2AuthorizedClientProvider authorizedClientProvider = context -> null;
	private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper = new DefaultContextAttributesMapper();

	/**
	 * Constructs an {@code AuthorizedClientServiceOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public DynamicClientRegistrationOAuth2AuthorizedClientManager(ClientRegistrationRepository clientRegistrationRepository,
																	OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Nullable
	@Override
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		OAuth2AuthorizedClient authorizedClient = authorizeRequest.getAuthorizedClient();
		Authentication principal = authorizeRequest.getPrincipal();

		OAuth2AuthorizationContext.Builder contextBuilder;
		if (authorizedClient != null) {
			contextBuilder = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient);
		} else {
			ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
			Assert.notNull(clientRegistration, "Could not find ClientRegistration with id '" + clientRegistrationId + "'");

			clientRegistrationId = resolveClientRegistrationId(clientRegistration, authorizeRequest);
			authorizedClient = this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principal.getName());

			if (authorizedClient != null) {
				contextBuilder = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient);
			} else {
				ClientRegistration mergedClientRegistration = mergeClientRegistrationOverridesIfNecessary(clientRegistration, authorizeRequest);
				if (mergedClientRegistration != null) {
					contextBuilder = OAuth2AuthorizationContext.withClientRegistration(mergedClientRegistration);
				} else {
					contextBuilder = OAuth2AuthorizationContext.withClientRegistration(clientRegistration);
				}
			}
		}
		OAuth2AuthorizationContext authorizationContext = contextBuilder
				.principal(principal)
				.attributes(attributes -> {
					Map<String, Object> contextAttributes = this.contextAttributesMapper.apply(authorizeRequest);
					if (!CollectionUtils.isEmpty(contextAttributes)) {
						attributes.putAll(contextAttributes);
					}
				})
				.build();

		authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);
		if (authorizedClient != null) {
			this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal);
		} else {
			// In the case of re-authorization, the returned `authorizedClient` may be null if re-authorization is not supported.
			// For these cases, return the provided `authorizationContext.authorizedClient`.
			if (authorizationContext.getAuthorizedClient() != null) {
				return authorizationContext.getAuthorizedClient();
			}
		}

		return authorizedClient;
	}

	private static String resolveClientRegistrationId(ClientRegistration clientRegistration, OAuth2AuthorizeRequest authorizeRequest) {
		Map<String, Object> clientRegistrationOverrides = getClientRegistrationOverrides(authorizeRequest);
		if (CollectionUtils.isEmpty(clientRegistrationOverrides)) {
			return clientRegistration.getRegistrationId();
		}
		return clientRegistration.getRegistrationId() + "[" + clientRegistrationOverrides.hashCode() + "]";
	}

	static ClientRegistration mergeClientRegistrationOverridesIfNecessary(ClientRegistration clientRegistration, OAuth2AuthorizeRequest authorizeRequest) {
		Map<String, Object> clientRegistrationOverrides = getClientRegistrationOverrides(authorizeRequest);
		if (CollectionUtils.isEmpty(clientRegistrationOverrides)) {
			return null;
		}

		ClientRegistration.Builder builder = from(clientRegistration);
		if (clientRegistrationOverrides.containsKey(SCOPES_ATTRIBUTE_NAME)) {
			Set<String> scopes = (Set<String>) clientRegistrationOverrides.get(SCOPES_ATTRIBUTE_NAME);
			builder.scope(scopes);
		}
		if (clientRegistrationOverrides.containsKey(AUTHORIZATION_GRANT_TYPE_ATTRIBUTE_NAME)) {
			AuthorizationGrantType authorizationGrantType = (AuthorizationGrantType) clientRegistrationOverrides.get(AUTHORIZATION_GRANT_TYPE_ATTRIBUTE_NAME);
			builder.authorizationGrantType(authorizationGrantType);
		}

		builder.registrationId(clientRegistration.getRegistrationId() + "[" + clientRegistrationOverrides.hashCode() + "]");

		return builder.build();
	}

	private static Map<String, Object> getClientRegistrationOverrides(OAuth2AuthorizeRequest authorizeRequest) {
		Map<String, Object> clientRegistrationOverrides = new HashMap<>();
		Set<String> scopes = authorizeRequest.getAttribute(SCOPES_ATTRIBUTE_NAME);
		if (!CollectionUtils.isEmpty(scopes)) {
			clientRegistrationOverrides.put(SCOPES_ATTRIBUTE_NAME, scopes);
		}
		AuthorizationGrantType authorizationGrantType = authorizeRequest.getAttribute(AUTHORIZATION_GRANT_TYPE_ATTRIBUTE_NAME);
		if (authorizationGrantType != null) {
			clientRegistrationOverrides.put(AUTHORIZATION_GRANT_TYPE_ATTRIBUTE_NAME, authorizationGrantType);
		}
		return clientRegistrationOverrides;
	}

	private static ClientRegistration.Builder from(ClientRegistration clientRegistration) {
		return ClientRegistration.withRegistrationId(clientRegistration.getRegistrationId())
				.clientId(clientRegistration.getClientId())
				.clientSecret(clientRegistration.getClientSecret())
				.clientAuthenticationMethod(clientRegistration.getClientAuthenticationMethod())
				.authorizationGrantType(clientRegistration.getAuthorizationGrantType())
				.redirectUriTemplate(clientRegistration.getRedirectUriTemplate())
				.scope(clientRegistration.getScopes())
				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
				.tokenUri(clientRegistration.getProviderDetails().getTokenUri())
				.userInfoUri(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
				.userInfoAuthenticationMethod(clientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())
				.userNameAttributeName(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
				.jwkSetUri(clientRegistration.getProviderDetails().getJwkSetUri())
				.providerConfigurationMetadata(clientRegistration.getProviderDetails().getConfigurationMetadata())
				.clientName(clientRegistration.getClientName());
	}

	/**
	 * Sets the {@link OAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client.
	 *
	 * @param authorizedClientProvider the {@link OAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client
	 */
	public void setAuthorizedClientProvider(OAuth2AuthorizedClientProvider authorizedClientProvider) {
		Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
		this.authorizedClientProvider = authorizedClientProvider;
	}

	/**
	 * Sets the {@code Function} used for mapping attribute(s) from the {@link OAuth2AuthorizeRequest} to a {@code Map} of attributes
	 * to be associated to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}.
	 *
	 * @param contextAttributesMapper the {@code Function} used for supplying the {@code Map} of attributes
	 *                                   to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}
	 */
	public void setContextAttributesMapper(Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}

	/**
	 * The default implementation of the {@link #setContextAttributesMapper(Function) contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper implements Function<OAuth2AuthorizeRequest, Map<String, Object>> {

		@Override
		public Map<String, Object> apply(OAuth2AuthorizeRequest authorizeRequest) {
			Map<String, Object> contextAttributes = Collections.emptyMap();
			String scope = authorizeRequest.getAttribute(OAuth2ParameterNames.SCOPE);
			if (StringUtils.hasText(scope)) {
				contextAttributes = new HashMap<>();
				contextAttributes.put(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME,
						StringUtils.delimitedListToStringArray(scope, " "));
			}
			return contextAttributes;
		}
	}
}
