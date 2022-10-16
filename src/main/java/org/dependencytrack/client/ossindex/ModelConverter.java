package org.dependencytrack.client.ossindex;

import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.persistence.QueryManager;
import us.springett.cvss.Cvss;
import us.springett.cvss.CvssV2;
import us.springett.cvss.CvssV3;
import us.springett.cvss.Score;

import java.math.BigDecimal;

public final class ModelConverter {

    private ModelConverter() {
    }

    public static Vulnerability convert(final QueryManager qm, final ComponentReportVulnerability reportedVuln) {
        final var vuln = new Vulnerability();
        if (reportedVuln.cve() != null) {
            vuln.setSource(Vulnerability.Source.NVD);
            vuln.setVulnId(reportedVuln.cve());
        } else {
            vuln.setSource(Vulnerability.Source.OSSINDEX);
            vuln.setVulnId(reportedVuln.id());
            vuln.setTitle(reportedVuln.title());
        }
        vuln.setDescription(reportedVuln.description());

        if (reportedVuln.cwe() != null) {
            final Cwe cwe = CweResolver.getInstance().resolve(qm, reportedVuln.cwe());
            if (cwe != null) {
                vuln.addCwe(cwe);
            }
        }

        final StringBuilder sb = new StringBuilder();
        final String reference = reportedVuln.reference();
        if (reference != null) {
            sb.append("* [").append(reference).append("](").append(reference).append(")\n");
        }
        for (String externalReference : reportedVuln.externalReferences()) {
            sb.append("* [").append(externalReference).append("](").append(externalReference).append(")\n");
        }
        final String references = sb.toString();
        if (references.length() > 0) {
            vuln.setReferences(references.substring(0, references.lastIndexOf("\n")));
        }

        if (reportedVuln.cvssVector() != null) {
            final Cvss cvss = Cvss.fromVector(reportedVuln.cvssVector());
            if (cvss != null) {
                final Score score = cvss.calculateScore();
                if (cvss instanceof CvssV2) {
                    vuln.setCvssV2BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    vuln.setCvssV2Vector(cvss.getVector());
                } else if (cvss instanceof CvssV3) {
                    vuln.setCvssV3BaseScore(BigDecimal.valueOf(score.getBaseScore()));
                    vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(score.getImpactSubScore()));
                    vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(score.getExploitabilitySubScore()));
                    vuln.setCvssV3Vector(cvss.getVector());
                }
            }
        }
        return vuln;
    }

}
