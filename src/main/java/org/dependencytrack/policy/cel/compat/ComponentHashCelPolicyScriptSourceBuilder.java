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
package org.dependencytrack.policy.cel.compat;

import alpine.common.logging.Logger;
import org.cyclonedx.model.Hash;
import org.dependencytrack.model.PolicyCondition;
import org.json.JSONObject;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class ComponentHashCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = Logger.getLogger(ComponentHashCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final Hash hash = extractHashValues(policyCondition);
        if (hash == null) {
            return null;
        }

        final String fieldName = hash.getAlgorithm().toLowerCase().replaceAll("-", "_");
        if (org.dependencytrack.proto.policy.v1.Component.getDescriptor().findFieldByName(fieldName) == null) {
            LOGGER.warn("Component does not have a field named %s".formatted(fieldName));
            return null;
        }

        return """
                component.%s == "%s"
                """.formatted(fieldName, escapeJson(hash.getValue()));
    }

    private static Hash extractHashValues(PolicyCondition condition) {
        if (condition.getValue() == null) {
            return null;
        }
        final JSONObject def = new JSONObject(condition.getValue());
        return new Hash(
                def.optString("algorithm", null),
                def.optString("value", null)
        );
    }

}
