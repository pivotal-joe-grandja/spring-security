/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.crypto.key;

import java.security.KeyPair;
import java.util.Collections;
import java.util.Set;

import javax.crypto.SecretKey;

/**
 * A source for cryptographic keys.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see KeyPair
 * @see SecretKey
 */
@FunctionalInterface
public interface KeySource {

	/**
	 * Returns a {@code Set} of {@code java.security.KeyPair}(s).
	 * @return a {@code Set} of {@code java.security.KeyPair}(s), or an empty {@code Set}
	 * if not available
	 */
	Set<KeyPair> getKeyPairs();

	/**
	 * Returns a {@code Set} of {@code javax.crypto.SecretKey}(s).
	 * @return a {@code Set} of {@code javax.crypto.SecretKey}(s), or an empty {@code Set}
	 * if not available
	 */
	default Set<SecretKey> getSecretKeys() {
		return Collections.emptySet();
	}

}
