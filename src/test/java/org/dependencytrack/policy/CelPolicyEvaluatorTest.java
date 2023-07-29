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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CelPolicyEvaluatorTest extends PersistenceCapableTest {

    @Test
    public void test() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, Subject.EXPRESSION, Operator.MATCHES, """
                'critical' in project.tags
                    && component.name == 'bar'
                    && vulns.exists(v, v.source == 'SNYK')
                    && in_license_group(component.license, 'Permissive')
                """);

        final var project = new Project();
        project.setName("foo");
        qm.persist(project);
        qm.bind(project, List.of(
                qm.createTag("public-facing"),
                qm.createTag("critical")
        ));

        final var license = new License();
        license.setName("MIT");
        license.setLicenseId("MIT");
        qm.persist(license);

        final var licenseGroup = new LicenseGroup();
        licenseGroup.setName("Permissive");
        licenseGroup.setLicenses(List.of(license));
        qm.persist(licenseGroup);

        final var component = new Component();
        component.setProject(project);
        component.setName("bar");
        component.setResolvedLicense(license);
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-123");
        vulnA.setSource(Vulnerability.Source.NVD);
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("SNYK-123");
        vulnB.setSource(Vulnerability.Source.SNYK);
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.addVulnerability(vulnB, component, AnalyzerIdentity.SNYK_ANALYZER);

        final var evaluator = new CelPolicyEvaluator();
        evaluator.setQueryManager(qm);

        assertThat(evaluator.evaluate(policy, component)).isNotEmpty();
    }

}
