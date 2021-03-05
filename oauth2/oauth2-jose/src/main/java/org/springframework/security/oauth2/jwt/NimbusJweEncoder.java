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

package org.springframework.security.oauth2.jwt;

import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author Joe Grandja
 */
public final class NimbusJweEncoder implements JwtEncoder {

	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private static final Converter<JoseHeader, JWEHeader> JWE_HEADER_CONVERTER = new JweHeaderConverter();

	private static final Converter<JwtClaimsSet, JWTClaimsSet> JWT_CLAIMS_SET_CONVERTER = new JwtClaimsSetConverter();

	private final JWKSource<SecurityContext> jwkSource;

	public NimbusJweEncoder(JWKSource<SecurityContext> jwkSource) {
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.jwkSource = jwkSource;
	}

	@Override
	public Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtEncodingException {
		Assert.notNull(headers, "headers cannot be null");
		Assert.notNull(claims, "claims cannot be null");

		JWTClaimsSet jwtClaimsSet = JWT_CLAIMS_SET_CONVERTER.convert(claims);
		Jwt jwe = encode(headers, new Payload<>(jwtClaimsSet.toString()));

		return new Jwt(jwe.getTokenValue(), claims.getIssuedAt(), claims.getExpiresAt(), jwe.getHeaders(),
				claims.getClaims());
	}

	@Override
	public Jwt encode(JoseHeader headers, Payload<?> payload) throws JwtEncodingException {
		Assert.notNull(headers, "headers cannot be null");
		Assert.notNull(payload, "payload cannot be null");

		JWEHeader jweHeader = JWE_HEADER_CONVERTER.convert(headers);

		JWK jwk = selectJwk(jweHeader);
		if (jwk == null) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK encryption key"));
		}

		jweHeader = addKeyIdentifierHeadersIfNecessary(jweHeader, jwk);
		headers = syncKeyIdentifierHeadersIfNecessary(headers, jweHeader);

		// FIXME
		// Resolve type of Payload.content
		// For now, assuming String type
		String content = (String) payload.getContent();

		JWEObject jweObject = new JWEObject(jweHeader, new com.nimbusds.jose.Payload(content));
		try {
			// FIXME
			// Resolve the JWEEncrypter based on the JWK key type
			// For now, assuming RSA key type
			jweObject.encrypt(new RSAEncrypter(jwk.toRSAKey()));
		}
		catch (JOSEException ex) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to encrypt the JWT -> " + ex.getMessage()),
					ex);
		}
		String jwe = jweObject.serialize();

		// FIXME
		// We need to pass in claimsPlaceholder to avoid IllegalArgumentException.
		// However, the claims should be `null` given that the payload is NOT a `JwtClaimsSet`.
		Map<String, Object> claimsPlaceholder = Collections.singletonMap("claim-placeholder", "value-placeholder");

		return new Jwt(jwe, null, null, headers.getHeaders(), claimsPlaceholder);
	}

	private JWK selectJwk(JWEHeader jweHeader) {
		JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWEHeader(jweHeader));

		List<JWK> jwks;
		try {
			jwks = this.jwkSource.get(jwkSelector, null);
		}
		catch (KeySourceException ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to select a JWK encryption key -> " + ex.getMessage()), ex);
		}

		if (jwks.size() > 1) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Found multiple JWK encryption keys for algorithm '" + jweHeader.getAlgorithm().getName() + "'"));
		}

		return !jwks.isEmpty() ? jwks.get(0) : null;
	}

	private static JWEHeader addKeyIdentifierHeadersIfNecessary(JWEHeader jweHeader, JWK jwk) {
		// Check if headers have already been added
		if (StringUtils.hasText(jweHeader.getKeyID()) && jweHeader.getX509CertSHA256Thumbprint() != null) {
			return jweHeader;
		}
		// Check if headers can be added from JWK
		if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
			return jweHeader;
		}

		JWEHeader.Builder headerBuilder = new JWEHeader.Builder(jweHeader);
		if (!StringUtils.hasText(jweHeader.getKeyID()) && StringUtils.hasText(jwk.getKeyID())) {
			headerBuilder.keyID(jwk.getKeyID());
		}
		if (jweHeader.getX509CertSHA256Thumbprint() == null && jwk.getX509CertSHA256Thumbprint() != null) {
			headerBuilder.x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint());
		}

		return headerBuilder.build();
	}

	private static JoseHeader syncKeyIdentifierHeadersIfNecessary(JoseHeader joseHeader, JWEHeader jweHeader) {
		String jwsHeaderX509SHA256Thumbprint = null;
		if (jweHeader.getX509CertSHA256Thumbprint() != null) {
			jwsHeaderX509SHA256Thumbprint = jweHeader.getX509CertSHA256Thumbprint().toString();
		}
		if (Objects.equals(joseHeader.getKeyId(), jweHeader.getKeyID())
				&& Objects.equals(joseHeader.getX509SHA256Thumbprint(), jwsHeaderX509SHA256Thumbprint)) {
			return joseHeader;
		}

		JoseHeader.Builder headerBuilder = JoseHeader.from(joseHeader);
		if (!Objects.equals(joseHeader.getKeyId(), jweHeader.getKeyID())) {
			headerBuilder.keyId(jweHeader.getKeyID());
		}
		if (!Objects.equals(joseHeader.getX509SHA256Thumbprint(), jwsHeaderX509SHA256Thumbprint)) {
			headerBuilder.x509SHA256Thumbprint(jwsHeaderX509SHA256Thumbprint);
		}

		return headerBuilder.build();
	}

	private static class JweHeaderConverter implements Converter<JoseHeader, JWEHeader> {

		@Override
		public JWEHeader convert(JoseHeader headers) {
			JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());
			EncryptionMethod encryptionMethod = EncryptionMethod.parse(headers.getHeader("enc"));
			JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, encryptionMethod);

			Set<String> critical = headers.getCritical();
			if (!CollectionUtils.isEmpty(critical)) {
				builder.criticalParams(critical);
			}

			String contentType = headers.getContentType();
			if (StringUtils.hasText(contentType)) {
				builder.contentType(contentType);
			}

			URL jwkSetUri = headers.getJwkSetUri();
			if (jwkSetUri != null) {
				try {
					builder.jwkURL(jwkSetUri.toURI());
				}
				catch (Exception ex) {
					throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
							"Failed to convert '" + JoseHeaderNames.JKU + "' JOSE header to a URI"), ex);
				}
			}

			Map<String, Object> jwk = headers.getJwk();
			if (!CollectionUtils.isEmpty(jwk)) {
				try {
					builder.jwk(JWK.parse(jwk));
				}
				catch (Exception ex) {
					throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
							"Failed to convert '" + JoseHeaderNames.JWK + "' JOSE header"), ex);
				}
			}

			String keyId = headers.getKeyId();
			if (StringUtils.hasText(keyId)) {
				builder.keyID(keyId);
			}

			String type = headers.getType();
			if (StringUtils.hasText(type)) {
				builder.type(new JOSEObjectType(type));
			}

			List<String> x509CertificateChain = headers.getX509CertificateChain();
			if (!CollectionUtils.isEmpty(x509CertificateChain)) {
				builder.x509CertChain(x509CertificateChain.stream().map(Base64::new).collect(Collectors.toList()));
			}

			String x509SHA1Thumbprint = headers.getX509SHA1Thumbprint();
			if (StringUtils.hasText(x509SHA1Thumbprint)) {
				builder.x509CertThumbprint(new Base64URL(x509SHA1Thumbprint));
			}

			String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
			if (StringUtils.hasText(x509SHA256Thumbprint)) {
				builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
			}

			URL x509Uri = headers.getX509Uri();
			if (x509Uri != null) {
				try {
					builder.x509CertURL(x509Uri.toURI());
				}
				catch (Exception ex) {
					throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
							"Failed to convert '" + JoseHeaderNames.X5U + "' JOSE header to a URI"), ex);
				}
			}

			Map<String, Object> customHeaders = headers.getHeaders().entrySet().stream()
					.filter((header) -> !JWSHeader.getRegisteredParameterNames().contains(header.getKey()))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			if (!CollectionUtils.isEmpty(customHeaders)) {
				builder.customParams(customHeaders);
			}

			return builder.build();
		}

	}

	private static class JwtClaimsSetConverter implements Converter<JwtClaimsSet, JWTClaimsSet> {

		@Override
		public JWTClaimsSet convert(JwtClaimsSet claims) {
			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

			URL issuer = claims.getIssuer();
			if (issuer != null) {
				builder.issuer(issuer.toExternalForm());
			}

			String subject = claims.getSubject();
			if (StringUtils.hasText(subject)) {
				builder.subject(subject);
			}

			List<String> audience = claims.getAudience();
			if (!CollectionUtils.isEmpty(audience)) {
				builder.audience(audience);
			}

			Instant issuedAt = claims.getIssuedAt();
			if (issuedAt != null) {
				builder.issueTime(Date.from(issuedAt));
			}

			Instant expiresAt = claims.getExpiresAt();
			if (expiresAt != null) {
				builder.expirationTime(Date.from(expiresAt));
			}

			Instant notBefore = claims.getNotBefore();
			if (notBefore != null) {
				builder.notBeforeTime(Date.from(notBefore));
			}

			String jwtId = claims.getId();
			if (StringUtils.hasText(jwtId)) {
				builder.jwtID(jwtId);
			}

			Map<String, Object> customClaims = claims.getClaims().entrySet().stream()
					.filter((claim) -> !JWTClaimsSet.getRegisteredNames().contains(claim.getKey()))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			if (!CollectionUtils.isEmpty(customClaims)) {
				customClaims.forEach(builder::claim);
			}

			return builder.build();
		}

	}

}
