/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core.oidc.discovery;

import org.springframework.security.oauth2.core.ClaimAccessor;

import java.net.URL;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the "claims" that can be returned
 * in the {@link OidcProviderConfiguration OpenID Provider Configuration} Response
 * from the Issuer's Discovery Endpoint.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see ClaimAccessor
 * @see OidcProviderMetadataClaimNames
 * @see OidcProviderConfiguration
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-session-1_0.html#OPMetadata">OpenID Connect Session Management 1.0</a>
 */
public interface OidcProviderMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Issuer identifier {@code (issuer)}.
	 *
	 * @return the Issuer identifier
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.ISSUER);
	}

	/**
	 * Returns the URL of the OAuth 2.0 Authorization Endpoint {@code (authorization_endpoint)}.
	 *
	 * @return the URL of the OAuth 2.0 Authorization Endpoint
	 */
	default URL getAuthorizationEndpoint() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Returns the URL of the OAuth 2.0 Token Endpoint {@code (token_endpoint)}.
	 *
	 * @return the URL of the OAuth 2.0 Token Endpoint
	 */
	default URL getTokenEndpoint() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token Endpoint {@code (token_endpoint_auth_methods_supported)}.
	 *
	 * @return the client authentication methods supported by the OAuth 2.0 Token Endpoint
	 */
	default List<String> getTokenEndpointAuthenticationMethods() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the JWS signing algorithms supported by the OAuth 2.0 Token Endpoint {@code (token_endpoint_auth_signing_alg_values_supported)}.
	 *
	 * @return the JWS signing algorithms supported by the OAuth 2.0 Token Endpoint
	 */
	default List<String> getTokenEndpointAuthenticationSigningAlgorithms() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED);
	}

	/**
	 * Returns the URL of the OpenID Connect 1.0 UserInfo Endpoint {@code (userinfo_endpoint)}.
	 *
	 * @return the URL of the OpenID Connect 1.0 UserInfo Endpoint
	 */
	default URL getUserInfoEndpoint() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.USERINFO_ENDPOINT);
	}

	/**
	 * Returns the URL of the JSON Web Key Set {@code (jwks_uri)}.
	 *
	 * @return the URL of the JSON Web Key Set
	 */
	default URL getJwksUri() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.JWKS_URI);
	}

	/**
	 * Returns the OAuth 2.0 {@code response_type} values supported {@code (response_types_supported)}.
	 *
	 * @return the OAuth 2.0 {@code response_type} values supported
	 */
	default List<String> getResponseTypes() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code grant_type} values supported {@code (grant_types_supported)}.
	 *
	 * @return the OAuth 2.0 {@code grant_type} values supported
	 */
	default List<String> getGrantTypes() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the Subject Identifier types supported {@code (subject_types_supported)}.
	 *
	 * @return the Subject Identifier types supported
	 */
	default List<String> getSubjectTypes() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the JWS signing algorithms supported for the ID Token to encode the claims in the JWT {@code (id_token_signing_alg_values_supported)}.
	 *
	 * @return the JWS signing algorithms supported for the ID Token to encode the claims in the JWT
	 */
	default List<String> getIdTokenSigningAlgorithms() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
	}

	/**
	 * Returns the JWE encryption algorithms ("alg" values) supported for the ID Token to encode the claims in the JWT {@code (id_token_encryption_alg_values_supported)}.
	 *
	 * @return the JWE encryption algorithms ("alg" values) supported for the ID Token to encode the claims in the JWT
	 */
	default List<String> getIdTokenKeyEncryptionAlgorithms() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED);
	}

	/**
	 * Returns the JWE encryption algorithms ("enc" values) supported for the ID Token to encode the claims in the JWT {@code (id_token_encryption_enc_values_supported)}.
	 *
	 * @return the JWE encryption algorithms ("enc" values) supported for the ID Token to encode the claims in the JWT
	 */
	default List<String> getIdTokenContentEncryptionAlgorithms() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code scope} values supported {@code (scopes_supported)}.
	 *
	 * @return the OAuth 2.0 {@code scope} values supported
	 */
	default List<String> getScopes() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED);
	}

	/**
	 * Returns the claim names of the claims supported {@code (claims_supported)}.
	 *
	 * @return the claim names of the claims supported
	 */
	default List<String> getClaimNames() {
		return this.getClaimAsStringList(OidcProviderMetadataClaimNames.CLAIMS_SUPPORTED);
	}

	/**
	 * Returns the URL of the OP iframe that supports cross-origin communications for session state information {@code (check_session_iframe)}.
	 *
	 * @return the URL of the OP iframe that supports cross-origin communications for session state information
	 */
	default URL getCheckSessionIFrame() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.CHECK_SESSION_IFRAME);
	}

	/**
	 * Returns the URL of the OP which a RP can perform a redirect to request that the End-User be logged out {@code (end_session_endpoint)}.
	 *
	 * @return the URL of the OP which a RP can perform a redirect to request that the End-User be logged out
	 */
	default URL getEndSessionEndpoint() {
		return this.getClaimAsURL(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT);
	}

}
