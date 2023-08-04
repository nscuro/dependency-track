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

import alpine.common.logging.Logger;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Timestamp;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Tag;
import org.dependencytrack.policy.CelPolicyScript.Requirement;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.tools.ScriptCreateException;
import org.projectnessie.cel.tools.ScriptException;

import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public abstract class AbstractCelPolicyEvaluator extends AbstractPolicyEvaluator {

    final Logger logger;
    private final CelPolicyScriptHost scriptHost;

    AbstractCelPolicyEvaluator() {
        this(CelPolicyScriptHost.getInstance());
    }

    AbstractCelPolicyEvaluator(final CelPolicyScriptHost scriptHost) {
        this.logger = Logger.getLogger(getClass());
        this.scriptHost = scriptHost;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final org.dependencytrack.model.Component component) {
        final List<PolicyCondition> conditions = extractSupportedConditions(policy);
        if (conditions.isEmpty()) {
            return Collections.emptyList();
        }

        final List<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs = conditions.stream()
                .map(condition -> {
                    final Optional<String> scriptSrc = getScriptSrc(condition);
                    if (scriptSrc.isEmpty()) {
                        logger.warn("Failed to determine script source for condition %s".formatted(condition.getUuid()));
                        return null;
                    }

                    final CelPolicyScript script;
                    try {
                        script = scriptHost.create(scriptSrc.get());
                    } catch (ScriptCreateException e) {
                        logger.error("Failed to create script for condition %s".formatted(condition.getUuid()), e);
                        return null;
                    }

                    return Pair.of(condition, script);
                })
                .filter(Objects::nonNull)
                .toList();

        final Set<Requirement> requirements = conditionScriptPairs.stream()
                .map(Pair::getRight)
                .map(CelPolicyScript::getRequirements)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        final Map<String, Object> scriptArgs = Map.of(
                "component", mapComponent(component, requirements),
                "project", mapProject(component.getProject(), requirements),
                "vulns", loadVulnerabilities(component, requirements)
        );

        final var violations = new ArrayList<PolicyConditionViolation>();

        for (final Pair<PolicyCondition, CelPolicyScript> conditionScriptPair : conditionScriptPairs) {
            final PolicyCondition condition = conditionScriptPair.getLeft();
            final CelPolicyScript script = conditionScriptPair.getRight();

            try {
                if (script.execute(scriptArgs)) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            } catch (ScriptException e) {
                throw new RuntimeException("Failed to evaluate script", e);
            }
        }

        return violations;
    }

    abstract Optional<String> getScriptSrc(final PolicyCondition policyCondition);

    private static Component mapComponent(final org.dependencytrack.model.Component component, final Set<Requirement> requirements) {
        final Component.Builder builder = Component.newBuilder()
                .setUuid(Optional.ofNullable(component.getUuid()).map(UUID::toString).orElse(""))
                .setGroup(trimToEmpty(component.getGroup()))
                .setName(trimToEmpty(component.getName()))
                .setVersion(trimToEmpty(component.getVersion()))
                .setCpe(trimToEmpty(component.getCpe()))
                .setPurl(Optional.ofNullable(component.getPurl())
                        .map(PackageURL::canonicalize)
                        .orElse(""))
                .setSwid(trimToEmpty(component.getSwidTagId()))
                .setMd5(trimToEmpty(component.getMd5()))
                .setSha1(trimToEmpty(component.getSha1()))
                .setSha256(trimToEmpty(component.getSha256()))
                .setSha384(trimToEmpty(component.getSha384()))
                .setSha512(trimToEmpty(component.getSha512()))
                .setSha3256(trimToEmpty(component.getSha3_256()))
                .setSha3384(trimToEmpty(component.getSha3_384()))
                .setSha3512(trimToEmpty(component.getSha3_512()))
                .setBlake2B256(trimToEmpty(component.getBlake2b_256()))
                .setBlake2B384(trimToEmpty(component.getBlake2b_384()))
                .setBlake2B512(trimToEmpty(component.getBlake2b_512()))
                .setBlake3(trimToEmpty(component.getBlake3()));

        if (component.getResolvedLicense() != null) {
            builder.setLicense(License.newBuilder()
                    .setId(trimToEmpty(component.getResolvedLicense().getLicenseId())));
        }

        return builder.build();
    }

    private static Project mapProject(final org.dependencytrack.model.Project project, final Set<Requirement> requirements) {
        if (!requirements.contains(Requirement.PROJECT)) {
            return Project.newBuilder().build();
        }

        return org.dependencytrack.proto.policy.v1.Project.newBuilder()
                .setUuid(Optional.ofNullable(project.getUuid()).map(UUID::toString).orElse(""))
                .setGroup(trimToEmpty(project.getGroup()))
                .setName(trimToEmpty(project.getName()))
                .setVersion(trimToEmpty(project.getVersion()))
                .addAllTags(project.getTags().stream()
                        .map(Tag::getName)
                        .toList())
                .build();
    }

    private List<Vulnerability> loadVulnerabilities(final org.dependencytrack.model.Component component, final Set<Requirement> requirements) {
        if (!requirements.contains(Requirement.VULNERABILITIES)) {
            return Collections.emptyList();
        }

        final Query<org.dependencytrack.model.Vulnerability> query =
                qm.getPersistenceManager().newQuery(org.dependencytrack.model.Vulnerability.class);
        query.setFilter("components.contains(:component)");
        query.setParameters(component);
        query.setResult("uuid, vulnId, source, cwes, created, published, updated");
        final List<VulnProjection> vulns;
        try {
            vulns = List.copyOf(query.executeResultList(VulnProjection.class));
        } finally {
            query.closeAll();
        }

        final List<Vulnerability.Builder> vulnBuilders = vulns.stream()
                .map(v -> {
                    final Vulnerability.Builder builder = Vulnerability.newBuilder()
                            .setUuid(v.uuid().toString())
                            .setId(trimToEmpty(v.vulnId()))
                            .setSource(trimToEmpty(v.source()));
                    if (v.cwes() != null && !v.cwes().isEmpty()) {
                        builder.addAllCwes(v.cwes());
                    }
                    if (v.created() != null) {
                        builder.setCreated(Timestamp.newBuilder()
                                .setSeconds(v.created().getSeconds()));
                    }
                    if (v.published() != null) {
                        builder.setPublished(Timestamp.newBuilder()
                                .setSeconds(v.published().getSeconds()));
                    }
                    if (v.updated() != null) {
                        builder.setUpdated(Timestamp.newBuilder()
                                .setSeconds(v.updated().getSeconds()));
                    }
                    return builder;
                })
                .toList();

        if (requirements.contains(Requirement.VULNERABILITY_ALIASES)) {
            // TODO: Fetch aliases
        }

        return vulnBuilders.stream().map(Vulnerability.Builder::build).toList();
    }

    public record VulnProjection(UUID uuid, String vulnId, String source, List<Integer> cwes,
                                 Date created, Date published, Date updated) {
    }

}
