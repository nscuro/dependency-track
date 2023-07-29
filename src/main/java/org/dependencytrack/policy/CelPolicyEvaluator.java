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
import alpine.server.cache.CacheManager;
import com.github.packageurl.PackageURL;
import org.apache.commons.codec.digest.DigestUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.proto.policy.v1.License;
import org.projectnessie.cel.EnvOption;
import org.projectnessie.cel.Library;
import org.projectnessie.cel.ProgramOption;
import org.projectnessie.cel.checker.Decls;
import org.projectnessie.cel.common.types.BoolT;
import org.projectnessie.cel.common.types.Err;
import org.projectnessie.cel.interpreter.functions.Overload;
import org.projectnessie.cel.tools.Script;
import org.projectnessie.cel.tools.ScriptCreateException;
import org.projectnessie.cel.tools.ScriptException;
import org.projectnessie.cel.tools.ScriptHost;

import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class CelPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(CelPolicyEvaluator.class);
    private static final ScriptHost SCRIPT_HOST = ScriptHost.newBuilder().build();

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.EXPRESSION;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyCondition> conditions = super.extractSupportedConditions(policy);

        final org.dependencytrack.proto.policy.v1.Component protoComponent = mapComponent(component);
        final org.dependencytrack.proto.policy.v1.Project protoProject = mapProject(component.getProject());
        final List<org.dependencytrack.proto.policy.v1.Vulnerability> protoVulns;

        // TODO: Make this more reliable. If we can access the AST of the script,
        //   we can determine better what data we need to load.
        final boolean shouldLoadVulns = conditions.stream()
                .map(PolicyCondition::getValue)
                .anyMatch(script -> script.matches("(?s).*\\bv\\..*"));
        if (shouldLoadVulns) {
            protoVulns = loadVulnerabilities(component);
        } else {
            protoVulns = Collections.emptyList();
        }

        final var violations = new ArrayList<PolicyConditionViolation>();
        for (final PolicyCondition condition : conditions) {
            final Script script = getCachedOrCompile(condition.getValue());

            try {
                final Boolean result = script.execute(Boolean.class, Map.of(
                        "component", protoComponent,
                        "project", protoProject,
                        "vulns", protoVulns
                ));
                if ((condition.getOperator() == PolicyCondition.Operator.MATCHES && result)
                        || (condition.getOperator() == PolicyCondition.Operator.NO_MATCH && !result)) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            } catch (ScriptException e) {
                throw new RuntimeException("Failed to evaluate script", e);
            }
        }

        return violations;
    }

    private org.dependencytrack.proto.policy.v1.Component mapComponent(final Component component) {
        final org.dependencytrack.proto.policy.v1.Component.Builder builder =
                org.dependencytrack.proto.policy.v1.Component.newBuilder()
                        .setUuid(component.getUuid().toString())
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

    private org.dependencytrack.proto.policy.v1.Project mapProject(final Project project) {
        return org.dependencytrack.proto.policy.v1.Project.newBuilder()
                .setUuid(project.getUuid().toString())
                .setGroup(trimToEmpty(project.getGroup()))
                .setName(trimToEmpty(project.getName()))
                .setVersion(trimToEmpty(project.getVersion()))
                .addAllTags(project.getTags().stream()
                        .map(Tag::getName)
                        .toList())
                .build();
    }

    private List<org.dependencytrack.proto.policy.v1.Vulnerability> loadVulnerabilities(final Component component) {
        final Query<Vulnerability> query = qm.getPersistenceManager().newQuery(Vulnerability.class);
        query.setFilter("components.contains(:component)");
        query.setParameters(component);
        query.setResult("uuid, vulnId, source");
        final List<VulnProjection> vulns;
        try {
            vulns = List.copyOf(query.executeResultList(VulnProjection.class));
        } finally {
            query.closeAll();
        }

        // TODO: Load aliases (can we bulk load them instead of executing a query for each vuln?)

        return vulns.stream()
                .map(v -> org.dependencytrack.proto.policy.v1.Vulnerability.newBuilder()
                        .setUuid(v.uuid().toString())
                        .setId(trimToEmpty(v.vulnId()))
                        .setSource(trimToEmpty(v.source()))
                        .build())
                .toList();
    }

    private static Script getCachedOrCompile(final String conditionScript) {
        final String scriptDigest = DigestUtils.sha256Hex(conditionScript);
        Script script = CacheManager.getInstance().get(Script.class, scriptDigest);
        if (script != null) {
            return script;
        }

        try {
            script = SCRIPT_HOST.buildScript(conditionScript)
                    .withLibraries(new CelLibrary())
                    .build();
        } catch (ScriptCreateException e) {
            throw new RuntimeException("Failed to create script", e);
        }

        CacheManager.getInstance().put(scriptDigest, script);
        return script;
    }

    public record VulnProjection(UUID uuid, String vulnId, String source) {
    }

    // TODO: Move to separate file
    // TODO: Use separate libraries for license, PURL, CVSS etc. functions
    private static class CelLibrary implements Library {

        @Override
        public List<EnvOption> getCompileOptions() {
            return List.of(
                    EnvOption.declarations(
                            Decls.newVar(
                                    "component",
                                    Decls.newObjectType(org.dependencytrack.proto.policy.v1.Component.getDescriptor().getFullName())),
                            Decls.newVar(
                                    "project",
                                    Decls.newObjectType(org.dependencytrack.proto.policy.v1.Project.getDescriptor().getFullName())),
                            Decls.newVar(
                                    "vulns",
                                    Decls.newListType(Decls.newObjectType(org.dependencytrack.proto.policy.v1.Vulnerability.getDescriptor().getFullName()))
                            ),
                            Decls.newFunction(
                                    "in_license_group",
                                    Decls.newOverload(
                                            "in_license_group_x",
                                            List.of(
                                                    Decls.newObjectType(org.dependencytrack.proto.policy.v1.License.getDescriptor().getFullName()),
                                                    Decls.String),
                                            Decls.Bool))
                    ),
                    EnvOption.types(
                            org.dependencytrack.proto.policy.v1.Component.getDefaultInstance(),
                            org.dependencytrack.proto.policy.v1.License.getDefaultInstance(),
                            org.dependencytrack.proto.policy.v1.Project.getDefaultInstance(),
                            org.dependencytrack.proto.policy.v1.Vulnerability.getDefaultInstance()
                    )
            );
        }

        @Override
        public List<ProgramOption> getProgramOptions() {
            return List.of(ProgramOption.functions(
                    Overload.binary(
                            "in_license_group",
                            (lhs, rhs) -> {
                                try (final var qm = new QueryManager()) {
                                    final var protoLicense = (org.dependencytrack.proto.policy.v1.License) lhs.value();
                                    final Query<LicenseGroup> query = qm.getPersistenceManager().newQuery(LicenseGroup.class);
                                    query.setFilter("name == :name && licenses.contains(license) && license.licenseId == :licenseId");
                                    query.declareVariables("org.dependencytrack.model.License license");
                                    query.setParameters((String) rhs.value(), protoLicense.getId());
                                    query.setResult("count(this)");
                                    try {
                                        return query.executeResultUnique(Long.class) > 0
                                                ? BoolT.True
                                                : BoolT.False;
                                    } finally {
                                        query.closeAll();
                                    }
                                } catch (RuntimeException e) {
                                    return Err.newErr(e, "%s", e.getMessage());
                                }
                            })
            ));
        }

    }

}
