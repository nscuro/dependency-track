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

import java.util.Optional;

import static org.apache.commons.lang3.StringEscapeUtils.escapeJson;

/**
 * Evaluates a components Common Platform Enumeration (CPE) against a policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class CpePolicyEvaluator extends AbstractCelPolicyEvaluator {

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.CPE;
    }

    @Override
    Optional<String> getScriptSrc(final PolicyCondition policyCondition) {
        final String scriptSrc = """
                component.cpe.matches("%s")
                """.formatted(escapeJson(policyCondition.getValue()));

        if (policyCondition.getOperator() == PolicyCondition.Operator.MATCHES) {
            return Optional.of(scriptSrc);
        } else if (policyCondition.getOperator() == PolicyCondition.Operator.NO_MATCH) {
            return Optional.of("!" + scriptSrc);
        }

        return Optional.empty();
    }

}
