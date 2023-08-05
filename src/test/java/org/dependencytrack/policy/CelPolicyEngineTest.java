package org.dependencytrack.policy;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CelPolicyEngineTest extends PersistenceCapableTest {

    @Test
    public void test() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EXPRESSION, PolicyCondition.Operator.MATCHES, """
                'critical' in project.tags
                    && component.name == 'bar'
                    && vulns.exists(v, v.source == 'SNYK')
                """);

        final var policy2 = qm.createPolicy("policy2", Policy.Operator.ALL, Policy.ViolationState.WARN);
        qm.createPolicyCondition(policy2, PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "CVE-123");

        final var policy3 = qm.createPolicy("policy3", Policy.Operator.ALL, Policy.ViolationState.INFO);
        final PolicyCondition condition3 = qm.createPolicyCondition(policy3, PolicyCondition.Subject.SWID_TAGID, PolicyCondition.Operator.IS, "foo");

        final var policy4 = qm.createPolicy("policy4", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy4, PolicyCondition.Subject.CWE, PolicyCondition.Operator.CONTAINS_ALL, "CWE-666, CWE-123, 555");

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
        vulnA.setCreated(Date.from(LocalDateTime.now().minusYears(1).toInstant(ZoneOffset.UTC)));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("SNYK-123");
        vulnB.setSource(Vulnerability.Source.SNYK);
        vulnB.setCwes(List.of(555, 666, 123));
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.addVulnerability(vulnB, component, AnalyzerIdentity.SNYK_ANALYZER);

        final var existingViolation = new PolicyViolation();
        existingViolation.setComponent(component);
        existingViolation.setPolicyCondition(condition3);
        existingViolation.setType(PolicyViolation.Type.OPERATIONAL);
        existingViolation.setTimestamp(new java.util.Date());
        qm.persist(existingViolation);

        final var policyEngine = new CelPolicyEngine();
        policyEngine.evaluateComponent(component.getUuid());

        final List<PolicyViolation> violations = qm.getAllPolicyViolations(component);
        assertThat(violations).isNotEmpty();
    }

}