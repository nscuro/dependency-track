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
package org.dependencytrack.policy;

import org.dependencytrack.model.PolicyCondition;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

public class LicenseCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    @Override
    public String apply(final PolicyCondition policyCondition) {
        if ("unresolved".equals(policyCondition.getValue())) {
            if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
                return """
                        !has(component.license)
                        """;
            } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
                return """
                        has(component.license)
                        """;
            }
        } else {
            final String escapedLicenseUuid = escapeJson(policyCondition.getValue());
            if (policyCondition.getOperator() == PolicyCondition.Operator.IS) {
                return """
                        component.license.uuid == "%s"
                        """.formatted(escapedLicenseUuid);
            } else if (policyCondition.getOperator() == PolicyCondition.Operator.IS_NOT) {
                return """
                        component.license.uuid != "%s"
                        """.formatted(escapedLicenseUuid);
            }
        }

        return null;
    }

}