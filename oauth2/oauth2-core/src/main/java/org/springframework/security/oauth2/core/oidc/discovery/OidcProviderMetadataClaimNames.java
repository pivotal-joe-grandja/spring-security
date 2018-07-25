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

/**
 * The names of the "claims" defined by the OpenID Connect Discovery 1.0 and
 * OpenID Connect Session Management 1.0 specifications, that can be returned
 * in the {@link OidcProviderConfiguration OpenID Provider Configuration} Response.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OidcProviderConfiguration
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-session-1_0.html#OPMetadata">OpenID Connect Session Management 1.0</a>
 */
public interface OidcProviderMetadataClaimNames {

	/**
	 * {@code issuer} - the Issuer identifier
	 */
	String ISSUER = "issuer";

	/**
	 * {@code authorization_endpoint} - the URL of the OAuth 2.0 Authorization Endpoint
	 */
	String AUTHORIZATION_ENDPOINT = "authorization_endpoint";

	/**
	 * {@code token_endpoint} - the URL of the OAuth 2.0 Token Endpoint
	 */
	String TOKEN_ENDPOINT = "token_endpoint";

	/**
	 * {@code token_endpoint_auth_methods_supported} - the client authentication methods supported by the OAuth 2.0 Token Endpoint
	 */
	String TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";

	/**
	 * {@code token_endpoint_auth_signing_alg_values_supported} - the JWS signing algorithms supported by the OAuth 2.0 Token Endpoint
	 */
	String TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported";

	/**
	 * {@code userinfo_endpoint} - the URL of the OpenID Connect 1.0 UserInfo Endpoint
	 */
	String USERINFO_ENDPOINT = "userinfo_endpoint";

	/**
	 * {@code jwks_uri} - the URL of the JSON Web Key Set
	 */
	String JWKS_URI = "jwks_uri";

	/**
	 * {@code response_types_supported} - the OAuth 2.0 {@code response_type} values supported
	 */
	String RESPONSE_TYPES_SUPPORTED = "response_types_supported";

	/**
	 * {@code grant_types_supported} - the OAuth 2.0 {@code grant_type} values supported
	 */
	String GRANT_TYPES_SUPPORTED = "grant_types_supported";

	/**
	 * {@code subject_types_supported} - the Subject Identifier types supported
	 */
	String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";

	/**
	 * {@code id_token_signing_alg_values_supported} - the JWS signing algorithms supported for the ID Token to encode the claims in the JWT
	 */
	String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";

	/**
	 * {@code id_token_encryption_alg_values_supported} - the JWE encryption algorithms ("alg" values) supported for the ID Token to encode the claims in the JWT
	 */
	String ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED = "id_token_encryption_alg_values_supported";

	/**
	 * {@code id_token_encryption_enc_values_supported} - the JWE encryption algorithms ("enc" values) supported for the ID Token to encode the claims in the JWT
	 */
	String ID_TOKEN_ENCRYPTION_ENC_VALUES_SUPPORTED = "id_token_encryption_enc_values_supported";

	/**
	 * {@code scopes_supported} - the OAuth 2.0 {@code scope} values supported
	 */
	String SCOPES_SUPPORTED = "scopes_supported";

	/**
	 * {@code claims_supported} - the claim names of the claims supported
	 */
	String CLAIMS_SUPPORTED = "claims_supported";

	/**
	 * {@code check_session_iframe} - the URL of the OP iframe that supports cross-origin communications for session state information
	 */
	String CHECK_SESSION_IFRAME = "check_session_iframe";

	/**
	 * {@code end_session_endpoint} - the URL of the OP which a RP can perform a redirect to request that the End-User be logged out
	 */
	String END_SESSION_ENDPOINT = "end_session_endpoint";

}
