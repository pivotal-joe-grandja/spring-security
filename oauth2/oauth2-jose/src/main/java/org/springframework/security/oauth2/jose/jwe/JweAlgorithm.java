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

package org.springframework.security.oauth2.jose.jwe;

import org.springframework.security.oauth2.jose.JwaAlgorithm;

/**
 * @author Joe Grandja
 */
public enum JweAlgorithm implements JwaAlgorithm {

	RSA_OAEP_256("RSA-OAEP-256");

	private final String name;

	JweAlgorithm(String name) {
		this.name = name;
	}

	@Override
	public String getName() {
		return this.name;
	}

	public static JweAlgorithm from(String name) {
		for (JweAlgorithm value : values()) {
			if (value.getName().equals(name)) {
				return value;
			}
		}
		return null;
	}

}
