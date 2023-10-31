/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.common.logging.Logger;
import alpine.model.ConfigProperty;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_GROUPS_REGEX;
import static org.dependencytrack.model.ConfigPropertyConstants.INTERNAL_COMPONENTS_NAMES_REGEX;

/**
 * @author nscuro
 * @since 3.7.0
 */
public final class InternalComponentIdentificationUtil {

    private enum PatternType {
        GROUP,
        NAME
    }

    private static final LoadingCache<PatternType, Pattern> CACHE = Caffeine.newBuilder()
            .build(InternalComponentIdentificationUtil::loadPattern);
    private static final Logger LOGGER = Logger.getLogger(InternalComponentIdentificationUtil.class);

    private InternalComponentIdentificationUtil() {
    }

    public static boolean isInternalComponent(final Component component) {
        return matchesPattern(component, PatternType.GROUP) || matchesPattern(component, PatternType.NAME);
    }

    public static void invalidateCache() {
        CACHE.invalidateAll();
    }

    private static boolean matchesPattern(final Component component, final PatternType patternType) {
        final Pattern pattern = CACHE.get(patternType);
        if (pattern == null) {
            return false;
        }

        final String valueToMatch = switch (patternType) {
            case GROUP -> component.getGroup();
            case NAME -> component.getName();
        };
        if (valueToMatch == null) {
            return false;
        }

        return pattern.matcher(valueToMatch).matches();
    }

    private static Pattern loadPattern(final PatternType patternType) {
        LOGGER.info("Loading pattern %s".formatted(patternType));

        final ConfigPropertyConstants propertyConstant = switch (patternType) {
            case GROUP -> INTERNAL_COMPONENTS_GROUPS_REGEX;
            case NAME -> INTERNAL_COMPONENTS_NAMES_REGEX;
        };

        final String configuredPattern;
        try (final var qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    propertyConstant.getGroupName(),
                    propertyConstant.getPropertyName()
            );

            configuredPattern = property != null
                    ? trimToNull(property.getPropertyValue())
                    : null;
        }

        return configuredPattern != null
                ? Pattern.compile(configuredPattern)
                : null;
    }

}
