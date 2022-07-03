package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import com.google.osv.ApiClient;
import com.google.osv.ApiException;
import com.google.osv.api.ApiApi;
import com.google.osv.model.OsvVulnerability;
import com.google.osv.model.V1BatchQuery;
import com.google.osv.model.V1BatchVulnerabilityList;
import com.google.osv.model.V1Query;
import com.google.osv.model.V1QueryPackage;
import com.google.osv.model.V1VulnerabilityList;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.OsvAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;

import java.util.List;
import java.util.Optional;

public class OsvAnalysisTask extends BaseComponentAnalyzerTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(OsvAnalysisTask.class);

    @Override
    public void inform(final Event e) {
        if (!(e instanceof OsvAnalysisEvent)) {
            return;
        }

        final var analysisEvent = (OsvAnalysisEvent) e;
        if (!analysisEvent.getComponents().isEmpty()) {
            analyze(analysisEvent.getComponents());
        }
    }

    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.OSV_ANALYZER;
    }

    @Override
    public void analyze(final List<Component> components) {
        final var osvApiClient = new ApiClient(HttpClientPool.getClient());
        final var osvApi = new ApiApi(osvApiClient);

        // TODO: Limit batch size to <= 1000
        final var batchQuery = new V1BatchQuery();
        for (final Component component : components) {
            batchQuery.addQueriesItem(new V1Query()
                    ._package(new V1QueryPackage().purl(component.getPurl().toString())));
        }

        final List<V1VulnerabilityList> vulnerabilityLists;
        try {
            final V1BatchVulnerabilityList queryResult = osvApi.oSVQueryAffectedBatch(batchQuery);

            vulnerabilityLists = queryResult.getResults();
            if (vulnerabilityLists == null || vulnerabilityLists.isEmpty()) {
                LOGGER.warn("OSV returned no results");
                return;
            }
        } catch (ApiException ex) {
            LOGGER.error("Performing batch query failed", ex);
            return;
        }

        // OSV will return a list of vulnerabilities for each query in the batch we submitted.
        // If no vulnerabilities are found, the respective list will be empty.
        // Correlation between input queries / components and results is based on their order.
        if (vulnerabilityLists.size() != components.size()) {
            LOGGER.warn("OSV returned " + vulnerabilityLists.size() + " results, but we expected " + components.size());
            return;
        }

        for (int i = 0; i < components.size(); i++) {
            final V1VulnerabilityList vulnerabilityList = vulnerabilityLists.get(i);
            if (vulnerabilityList.getVulns() == null || vulnerabilityList.getVulns().isEmpty()) {
                LOGGER.info("No vulnerabilities found for component " + components.get(i).getPurl());
                continue;
            }

            try (final var qm = new QueryManager()) {
                final var component = qm.getObjectById(Component.class, components.get(i).getId());

                for (OsvVulnerability osvVuln : vulnerabilityList.getVulns()) {
                    // Do we know this vulnerability already?
                    Vulnerability vuln = resolveVulnerability(qm, osvVuln.getId());

                    if (vuln == null) {
                        try {
                            // Vulnerabilities in batch query responses only contain their respective ID.
                            // If we need more fields, we have to explicitly request them.
                            // TODO: Cache these responses?
                            osvVuln = osvApi.oSVGetVulnById(osvVuln.getId());
                        } catch (ApiException e) {
                            LOGGER.error("Requesting details for vulnerability " + osvVuln.getId() + " failed", e);
                            continue;
                        }

                        // Primary ID of the vulnerability is unknown, but maybe we know one of its aliases?
                        if (osvVuln.getAliases() != null && !osvVuln.getAliases().isEmpty()) {
                            for (final String alias : osvVuln.getAliases()) {
                                vuln = resolveVulnerability(qm, alias);
                                if (vuln != null) {
                                    break;
                                }
                            }
                        }

                        // Vulnerability is not known to us yet, so we have to create it.
                        if (vuln == null) {
                            vuln = new Vulnerability();

                            // Similar to how it's done in OssIndexAnalysisTask, we prefer using the ID
                            // of the authoritative vulnerability source. We also prioritize CVE/NVD over GHSA.
                            // Vulnerability data will ultimately be overridden by those sources once
                            // Dependency-Track starts mirroring them.
                            final Optional<String> optCve = resolveCve(osvVuln);
                            final Optional<String> optGhsaId = resolveGhsaId(osvVuln);
                            if (optCve.isPresent()) {
                                vuln.setSource(Vulnerability.Source.NVD);
                                vuln.setVulnId(optCve.get());
                            } else if (optGhsaId.isPresent()) {
                                vuln.setSource(Vulnerability.Source.GITHUB);
                                vuln.setVulnId(optGhsaId.get());
                            } else {
                                vuln.setSource(Vulnerability.Source.OSV);
                                vuln.setVulnId(osvVuln.getId());
                            }

                            vuln.setTitle(StringUtils.truncate(osvVuln.getSummary(), 255));
                            vuln.setDescription(osvVuln.getDetails());

                            // TODO: Parse more details

                            vuln = qm.createVulnerability(vuln, false);
                        }
                    }

                    LOGGER.info(osvVuln.getId() + " matched to " + vuln.getVulnId() + " (" + vuln.getSource() + ")");
                    NotificationUtil.analyzeNotificationCriteria(qm, vuln, component);
                    qm.addVulnerability(vuln, component, this.getAnalyzerIdentity(), osvVuln.getId(), "https://osv.dev/vulnerability/" + osvVuln.getId());
                }
            }
        }
    }

    @Override
    public boolean isCapable(final Component component) {
        return component.getPurl() != null
                && component.getPurl().getName() != null
                && component.getPurl().getVersion() != null;
    }

    private Vulnerability resolveVulnerability(final QueryManager qm, final String vulnerabilityId) {
        return qm.getVulnerabilityByVulnId(resolveVulnerabilitySource(vulnerabilityId), vulnerabilityId);
    }

    private Vulnerability.Source resolveVulnerabilitySource(final String vulnerabilityId) {
        if (StringUtils.startsWith(vulnerabilityId, "CVE-")) {
            return Vulnerability.Source.NVD;
        } else if (StringUtils.startsWith(vulnerabilityId, "GHSA-")) {
            return Vulnerability.Source.GITHUB;
        }

        return Vulnerability.Source.OSV;
    }

    private Optional<String> resolveCve(final OsvVulnerability osvVuln) {
        if (resolveVulnerabilitySource(osvVuln.getId()) == Vulnerability.Source.NVD) {
            return Optional.ofNullable(osvVuln.getId());
        }

        return Optional.ofNullable(osvVuln.getAliases()).orElseGet(List::of).stream()
                .filter(alias -> resolveVulnerabilitySource(alias) == Vulnerability.Source.NVD)
                .findFirst();
    }

    private Optional<String> resolveGhsaId(final OsvVulnerability osvVuln) {
        if (resolveVulnerabilitySource(osvVuln.getId()) == Vulnerability.Source.GITHUB) {
            return Optional.ofNullable(osvVuln.getId());
        }

        return Optional.ofNullable(osvVuln.getAliases()).orElseGet(List::of).stream()
                .filter(alias -> resolveVulnerabilitySource(alias) == Vulnerability.Source.GITHUB)
                .findFirst();
    }

}
