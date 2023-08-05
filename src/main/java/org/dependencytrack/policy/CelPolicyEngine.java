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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.CelPolicyScript.Requirement;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.dependencytrack.util.NotificationUtil;
import org.projectnessie.cel.tools.ScriptCreateException;
import org.projectnessie.cel.tools.ScriptException;

import javax.jdo.Query;
import javax.jdo.Transaction;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class CelPolicyEngine {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyEngine.class);
    private static final Map<Subject, CelPolicyScriptSourceBuilder> SCRIPT_BUILDERS = Map.of(
            Subject.CPE, new CpeCelPolicyScriptSourceBuilder(),
            Subject.COMPONENT_HASH, new ComponentHashCelPolicyScriptSourceBuilder(),
            Subject.CWE, new CweCelPolicyScriptSourceBuilder(),
            Subject.EXPRESSION, PolicyCondition::getValue,
            Subject.LICENSE, new LicenseCelPolicyScriptSourceBuilder(),
            Subject.PACKAGE_URL, new PackageUrlCelPolicyScriptSourceBuilder(),
            Subject.SEVERITY, new SeverityCelPolicyScriptSourceBuilder(),
            Subject.SWID_TAGID, new SwidTagIdCelPolicyScriptSourceBuilder(),
            Subject.VULNERABILITY_ID, new VulnerabilityIdCelPolicyScriptSourceBuilder()
    );

    private final CelPolicyScriptHost scriptHost;

    public CelPolicyEngine() {
        this(CelPolicyScriptHost.getInstance());
    }

    CelPolicyEngine(CelPolicyScriptHost scriptHost) {
        this.scriptHost = scriptHost;
    }

    public void evaluateProject(final UUID projectUuid) {
        // TODO
    }

    public void evaluateComponent(final UUID componentUuid) {
        try (final var qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                LOGGER.warn("Component with UUID %s does not exist".formatted(componentUuid));
                return;
            }

            final List<Policy> policies = getApplicablePolicies(qm, component.getProject());
            if (policies.isEmpty()) {
                // With no applicable policies, there's no way to resolve violations.
                // As a compensation, simply delete all violations associated with the component.
                reconcileViolations(qm, Collections.emptyList());
                return;
            }

            // Pre-compile the CEL scripts for all conditions of all applicable policies.
            // Compiled scripts are cached in-memory by CelPolicyScriptHost, so if the same script
            // is encountered for multiple components (possibly concurrently), the compilation is
            // a one-time effort.
            LOGGER.info("Compiling policy scripts for component %s".formatted(componentUuid)); // TODO: Change to debug
            final List<Pair<PolicyCondition, CelPolicyScript>> conditionScriptPairs = policies.stream()
                    .map(Policy::getPolicyConditions)
                    .flatMap(Collection::stream)
                    .map(policyCondition -> {
                        final CelPolicyScriptSourceBuilder scriptBuilder = SCRIPT_BUILDERS.get(policyCondition.getSubject());
                        if (scriptBuilder == null) {
                            LOGGER.warn("No script builder found that is capable of handling subjects of type %s".formatted(policyCondition.getSubject()));
                            return null;
                        }

                        final String scriptSrc = scriptBuilder.apply(policyCondition);
                        if (scriptSrc == null) {
                            LOGGER.warn("Script builder was unable to create a script for condition %s".formatted(policyCondition.getUuid()));
                            return null;
                        }

                        return Pair.of(policyCondition, scriptSrc);
                    })
                    .filter(Objects::nonNull)
                    .map(conditionScriptSrcPair -> {
                        final CelPolicyScript script;
                        try {
                            script = scriptHost.compile(conditionScriptSrcPair.getRight());
                        } catch (ScriptCreateException e) {
                            throw new RuntimeException(e);
                        }

                        return Pair.of(conditionScriptSrcPair.getLeft(), script);
                    })
                    .toList();

            // Check what kind of data we need to evaluate all policy conditions.
            //
            // Some conditions will be very simple and won't require us to load additional data (e.g. "component PURL matches 'XYZ'"),
            // whereas other conditions can span across multiple models, forcing us to load more data
            // (e.g. "project has tag 'public-facing' and component has a vulnerability with severity 'critical'").
            //
            // What we want to avoid is loading data we don't need, and loading it multiple times.
            // Instead, only load what's really needed, and only do so once.
            LOGGER.info("Determining evaluation requirements for component %s and %d policy conditions"  // TODO: Change to debug
                    .formatted(componentUuid, conditionScriptPairs.size()));
            final Set<Requirement> requirements = conditionScriptPairs.stream()
                    .map(Pair::getRight)
                    .map(CelPolicyScript::getRequirements)
                    .flatMap(Collection::stream)
                    .collect(Collectors.toSet());

            // Prepare the script arguments according to the requirements gathered before.
            LOGGER.info("Building script arguments for component %s and requirements %s"  // TODO: Change to debug
                    .formatted(componentUuid, requirements));
            final Map<String, Object> scriptArgs = Map.of(
                    "component", mapComponent(component, requirements),
                    "project", mapProject(component.getProject(), requirements),
                    "vulns", loadVulnerabilities(qm, component, requirements)
            );

            LOGGER.info("Evaluating component %s against %d applicable policy conditions"  // TODO: Change to debug
                    .formatted(componentUuid, conditionScriptPairs.size()));
            final var conditionsViolated = new HashSet<PolicyCondition>();
            for (final Pair<PolicyCondition, CelPolicyScript> conditionScriptPair : conditionScriptPairs) {
                final PolicyCondition condition = conditionScriptPair.getLeft();
                final CelPolicyScript script = conditionScriptPair.getRight();

                try {
                    if (script.execute(scriptArgs)) {
                        conditionsViolated.add(condition);
                    }
                } catch (ScriptException e) {
                    throw new RuntimeException("Failed to evaluate script", e);
                }
            }

            // Group the detected condition violations by policy. Necessary to be able to evaluate
            // each policy's operator (ANY, ALL).
            LOGGER.info("Detected violation of %d policy conditions for component %s; Evaluating policy operators"  // TODO: Change to debug
                    .formatted(conditionsViolated.size(), componentUuid));
            final Map<Policy, List<PolicyCondition>> violatedConditionsByPolicy = conditionsViolated.stream()
                    .collect(Collectors.groupingBy(PolicyCondition::getPolicy));

            // Create policy violations, but only do so when the detected condition violations
            // match the configured policy operator. When the operator is ALL, and not all conditions
            // of the policy were violated, we don't want to create any violations.
            final List<PolicyViolation> violations = violatedConditionsByPolicy.entrySet().stream()
                    .flatMap(policyAndViolatedConditions -> {
                        final Policy policy = policyAndViolatedConditions.getKey();
                        final List<PolicyCondition> violatedConditions = policyAndViolatedConditions.getValue();

                        if ((policy.getOperator() == Policy.Operator.ANY && !violatedConditions.isEmpty())
                                || (policy.getOperator() == Policy.Operator.ALL && violatedConditions.size() == policy.getPolicyConditions().size())) {
                            return violatedConditions.stream()
                                    .map(condition -> {
                                        final var violation = new PolicyViolation();
                                        violation.setComponent(component);
                                        violation.setPolicyCondition(condition);
                                        violation.setType(determineViolationType(condition.getSubject()));
                                        violation.setTimestamp(new Date());
                                        return violation;
                                    });
                        }

                        return Stream.empty();
                    })
                    .toList();

            // Reconcile the violations created above with what's already in the database.
            // Create new records if necessary, and delete records that are no longer current.
            final List<PolicyViolation> newViolations = reconcileViolations(qm, violations);

            // Notify users about any new violations.
            for (final PolicyViolation newViolation : newViolations) {
                NotificationUtil.analyzeNotificationCriteria(qm, newViolation);
            }
        }

        LOGGER.info("Policy evaluation completed for component %s".formatted(componentUuid));  // TODO: Change to debug
    }

    // TODO: Move to PolicyQueryManager
    private static List<Policy> getApplicablePolicies(final QueryManager qm, final Project project) {
        var filter = """
                (this.projects.isEmpty() && this.tags.isEmpty())
                    || (this.projects.contains(:project)
                """;
        var params = new HashMap<String, Object>();
        params.put("project", project);

        // To compensate for missing support for recursion of Common Table Expressions (CTEs)
        // in JDO, we have to fetch the UUIDs of all parent projects upfront. Otherwise, we'll
        // not be able to evaluate whether the policy is inherited from parent projects.
        var variables = "";
        final List<UUID> parentUuids = getParents(qm, project);
        if (!parentUuids.isEmpty()) {
            filter += """
                    || (this.includeChildren
                        && this.projects.contains(parentVar)
                        && :parentUuids.contains(parentVar.uuid))
                    """;
            variables += "org.dependencytrack.model.Project parentVar";
            params.put("parentUuids", parentUuids);
        }
        filter += ")";

        // DataNucleus generates an invalid SQL query when using the idiomatic solution.
        // The following works, but it's ugly and likely doesn't perform well if the project
        // has many tags. Worth trying the idiomatic way again once DN has been updated to > 6.0.4.
        //
        // filter += " || (this.tags.contains(commonTag) && :project.tags.contains(commonTag))";
        // variables += "org.dependencytrack.model.Tag commonTag";
        if (project.getTags() != null && !project.getTags().isEmpty()) {
            filter += " || (";
            for (int i = 0; i < project.getTags().size(); i++) {
                filter += "this.tags.contains(:tag" + i + ")";
                params.put("tag" + i, project.getTags().get(i));
                if (i < (project.getTags().size() - 1)) {
                    filter += " || ";
                }
            }
            filter += ")";
        }

        final List<Policy> policies;
        final Query<Policy> query = qm.getPersistenceManager().newQuery(Policy.class);
        try {
            query.setFilter(filter);
            query.setNamedParameters(params);
            if (!variables.isEmpty()) {
                query.declareVariables(variables);
            }
            policies = List.copyOf(query.executeList());
        } finally {
            query.closeAll();
        }

        return policies;
    }

    // TODO: Move to ProjectQueryManager
    private static List<UUID> getParents(final QueryManager qm, final Project project) {
        return getParents(qm, project.getUuid(), new ArrayList<>());
    }

    // TODO: Move to ProjectQueryManager
    private static List<UUID> getParents(final QueryManager qm, final UUID uuid, final List<UUID> parents) {
        final UUID parentUuid;
        final Query<Project> query = qm.getPersistenceManager().newQuery(Project.class);
        try {
            query.setFilter("uuid == :uuid && parent != null");
            query.setParameters(uuid);
            query.setResult("parent.uuid");
            parentUuid = query.executeResultUnique(UUID.class);
        } finally {
            query.closeAll();
        }

        if (parentUuid == null) {
            return parents;
        }

        parents.add(parentUuid);
        return getParents(qm, parentUuid, parents);
    }

    private static org.dependencytrack.proto.policy.v1.Component mapComponent(final org.dependencytrack.model.Component component,
                                                                              final Set<Requirement> requirements) {
        final org.dependencytrack.proto.policy.v1.Component.Builder builder = org.dependencytrack.proto.policy.v1.Component.newBuilder()
                .setUuid(Optional.ofNullable(component.getUuid()).map(UUID::toString).orElse(""))
                .setGroup(trimToEmpty(component.getGroup()))
                .setName(trimToEmpty(component.getName()))
                .setVersion(trimToEmpty(component.getVersion()))
                .setCpe(trimToEmpty(component.getCpe()))
                .setPurl(Optional.ofNullable(component.getPurl())
                        .map(PackageURL::canonicalize)
                        .orElse(""))
                .setSwidTagId(trimToEmpty(component.getSwidTagId()))
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

    private static org.dependencytrack.proto.policy.v1.Project mapProject(final org.dependencytrack.model.Project project,
                                                                          final Set<Requirement> requirements) {
        if (!requirements.contains(Requirement.PROJECT)) {
            return org.dependencytrack.proto.policy.v1.Project.newBuilder().build();
        }

        return org.dependencytrack.proto.policy.v1.Project.newBuilder()
                .setUuid(Optional.ofNullable(project.getUuid()).map(UUID::toString).orElse(""))
                .setGroup(trimToEmpty(project.getGroup()))
                .setName(trimToEmpty(project.getName()))
                .setVersion(trimToEmpty(project.getVersion()))
                .addAllTags(project.getTags().stream()
                        .map(Tag::getName)
                        .toList())
                .setCpe(trimToEmpty(project.getCpe()))
                .setPurl(Optional.ofNullable(project.getPurl())
                        .map(PackageURL::canonicalize)
                        .orElse(""))
                .setSwidTagId(trimToEmpty(project.getSwidTagId()))
                .build();
    }

    private static List<Vulnerability> loadVulnerabilities(final QueryManager qm,
                                                           final org.dependencytrack.model.Component component,
                                                           final Set<Requirement> requirements) {
        if (!requirements.contains(Requirement.VULNERABILITIES)) {
            return Collections.emptyList();
        }

        final Query<org.dependencytrack.model.Vulnerability> query =
                qm.getPersistenceManager().newQuery(org.dependencytrack.model.Vulnerability.class);
        query.setFilter("components.contains(:component)");
        query.setParameters(component);
        query.setResult("""
                uuid,
                vulnId,
                source,
                cwes,
                created,
                published,
                updated,
                cvssV2BaseScore,
                cvssV2ImpactSubScore,
                cvssV2ExploitabilitySubScore,
                cvssV2Vector,
                cvssV3BaseScore,
                cvssV3ImpactSubScore,
                cvssV3ExploitabilitySubScore,
                cvssV3Vector,
                owaspRRLikelihoodScore,
                owaspRRTechnicalImpactScore,
                owaspRRBusinessImpactScore,
                owaspRRVector,
                severity,
                epssScore,
                epssPercentile
                """);
        final List<org.dependencytrack.model.Vulnerability> vulns;
        try {
            vulns = List.copyOf(query.executeResultList(org.dependencytrack.model.Vulnerability.class));
        } finally {
            query.closeAll();
        }

        final List<Vulnerability.Builder> vulnBuilders = vulns.stream()
                .map(v -> {
                    final Vulnerability.Builder builder = Vulnerability.newBuilder()
                            .setUuid(v.getUuid().toString())
                            .setId(trimToEmpty(v.getVulnId()))
                            .setSource(trimToEmpty(v.getSource()))
                            .setCvssv2Vector(trimToEmpty(v.getCvssV2Vector()))
                            .setCvssv3Vector(trimToEmpty(v.getCvssV3Vector()))
                            .setSeverity(v.getSeverity().name());
                    Optional.ofNullable(v.getCwes()).ifPresent(builder::addAllCwes);
                    Optional.ofNullable(v.getCvssV2BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2BaseScore);
                    Optional.ofNullable(v.getCvssV2ImpactSubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ImpactSubscore);
                    Optional.ofNullable(v.getCvssV2ExploitabilitySubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv2ExploitabilitySubscore);
                    Optional.ofNullable(v.getCvssV3BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3BaseScore);
                    Optional.ofNullable(v.getCvssV3ImpactSubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ImpactSubscore);
                    Optional.ofNullable(v.getCvssV3ExploitabilitySubScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssv3ExploitabilitySubscore);
                    Optional.ofNullable(v.getEpssScore()).map(BigDecimal::doubleValue).ifPresent(builder::setEpssScore);
                    Optional.ofNullable(v.getEpssPercentile()).map(BigDecimal::doubleValue).ifPresent(builder::setEpssPercentile);
                    Optional.ofNullable(v.getCreated()).map(Date::getSeconds).map(Timestamp.newBuilder()::setSeconds).ifPresent(builder::setCreated);
                    Optional.ofNullable(v.getPublished()).map(Date::getSeconds).map(Timestamp.newBuilder()::setSeconds).ifPresent(builder::setPublished);
                    Optional.ofNullable(v.getUpdated()).map(Date::getSeconds).map(Timestamp.newBuilder()::setSeconds).ifPresent(builder::setUpdated);
                    return builder;
                })
                .toList();

        if (requirements.contains(Requirement.VULNERABILITY_ALIASES)) {
            // TODO: Fetch aliases
        }

        return vulnBuilders.stream()
                .map(Vulnerability.Builder::build)
                .toList();
    }

    private static PolicyViolation.Type determineViolationType(final PolicyCondition.Subject subject) {
        if (subject == null) {
            return null;
        }
        return switch (subject) {
            case CWE, SEVERITY, VULNERABILITY_ID -> PolicyViolation.Type.SECURITY;
            case AGE, COORDINATES, PACKAGE_URL, CPE, SWID_TAGID, COMPONENT_HASH, VERSION, EXPRESSION, VERSION_DISTANCE ->
                    PolicyViolation.Type.OPERATIONAL;
            case LICENSE, LICENSE_GROUP -> PolicyViolation.Type.LICENSE;
        };
    }

    // TODO: Move to PolicyQueryManager
    private static List<PolicyViolation> reconcileViolations(final QueryManager qm, final List<PolicyViolation> violations) {
        final var newViolations = new ArrayList<PolicyViolation>();

        final Transaction trx = qm.getPersistenceManager().currentTransaction();
        try {
            trx.begin();

            final var violationIdsToKeep = new HashSet<Long>();

            for (final PolicyViolation violation : violations) {
                final Query<PolicyViolation> query = qm.getPersistenceManager().newQuery(PolicyViolation.class);
                query.setFilter("component == :component && policyCondition == :policyCondition && type == :type");
                query.setNamedParameters(Map.of(
                        "component", violation.getComponent(),
                        "policyCondition", violation.getPolicyCondition(),
                        "type", violation.getType()
                ));
                query.setResult("id");

                final Long existingViolationId;
                try {
                    existingViolationId = query.executeResultUnique(Long.class);
                } finally {
                    query.closeAll();
                }

                if (existingViolationId != null) {
                    violationIdsToKeep.add(existingViolationId);
                } else {
                    qm.getPersistenceManager().makePersistent(violation);
                    violationIdsToKeep.add(violation.getId());
                    newViolations.add(violation);
                }
            }

            final Query<PolicyViolation> deleteQuery = qm.getPersistenceManager().newQuery(PolicyViolation.class);
            deleteQuery.setFilter("!:ids.contains(id)");
            try {
                final long violationsDeleted = deleteQuery.deletePersistentAll(violationIdsToKeep);
                LOGGER.info("Deleted %s outdated violations".formatted(violationsDeleted)); // TODO: Change to debug; Add component UUID
            } finally {
                deleteQuery.closeAll();
            }

            trx.commit();
        } finally {
            if (trx.isActive()) {
                trx.rollback();
            }
        }

        return newViolations;
    }

}
