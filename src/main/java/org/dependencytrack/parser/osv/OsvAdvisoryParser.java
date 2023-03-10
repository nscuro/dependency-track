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
package org.dependencytrack.parser.osv;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.common.Jackson;
import org.dependencytrack.model.Severity;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

/*
    Parser for Google OSV, an aggregator of vulnerability databases including GitHub Security Advisories, PyPA, RustSec, and Global Security Database, and more.
 */
public class OsvAdvisoryParser {

    public OsvAdvisory parse(final JsonNode object) {

        OsvAdvisory advisory = null;

        // initial check if advisory is valid or withdrawn
        String withdrawn = Jackson.optString(object, "withdrawn");

        if(object != null && withdrawn == null) {

            advisory = new OsvAdvisory();
            advisory.setId(Jackson.optString(object, "id"));
            advisory.setSummary(trimSummary(Jackson.optString(object, "summary")));
            advisory.setDetails(Jackson.optString(object, "details"));
            advisory.setPublished(jsonStringToTimestamp(Jackson.optString(object, "published")));
            advisory.setModified(jsonStringToTimestamp(Jackson.optString(object, "modified")));
            advisory.setSchema_version(Jackson.optString(object, "schema_version"));

            final ArrayNode references = Jackson.optArray(object, "references");
            if (references != null) {
                for (int i=0; i<references.size(); i++) {
                    final JsonNode reference = references.get(i);
                    final String url = Jackson.optString(reference, "url");
                    advisory.addReference(url);
                }
            }

            final ArrayNode credits = Jackson.optArray(object, "credits");
            if (credits != null) {
                for (int i=0; i<credits.size(); i++) {
                    final JsonNode credit = credits.get(i);
                    final String name = Jackson.optString(credit, "name");
                    advisory.addCredit(name);
                }
            }

            final ArrayNode aliases = Jackson.optArray(object, "aliases");
            if(aliases != null) {
                for (int i=0; i<aliases.size(); i++) {
                    advisory.addAlias(Jackson.optString(aliases, i));
                }
            }

            final JsonNode databaseSpecific = Jackson.optNode(object, "database_specific");
            if (databaseSpecific != null) {
                advisory.setSeverity(Jackson.optString(databaseSpecific, "severity"));
                final ArrayNode cweIds = Jackson.optArray(databaseSpecific, "cwe_ids");
                if(cweIds != null) {
                    for (int i=0; i<cweIds.size(); i++) {
                        advisory.addCweId(Jackson.optString(cweIds, i));
                    }
                }
            }

            final ArrayNode cvssList = Jackson.optArray(object, "severity");
            if (cvssList != null) {
                for (int i=0; i<cvssList.size(); i++) {
                    final JsonNode cvss = cvssList.get(i);
                    final String type = Jackson.optString(cvss, "type");
                    if (type.equalsIgnoreCase("CVSS_V3")) {
                        advisory.setCvssV3Vector(Jackson.optString(cvss, "score"));
                    }
                    if (type.equalsIgnoreCase("CVSS_V2")) {
                        advisory.setCvssV2Vector(Jackson.optString(cvss, "score"));
                    }
                }
            }

            final List<OsvAffectedPackage> affectedPackages = parseAffectedPackages(object);
            advisory.setAffectedPackages(affectedPackages);
        }
        return advisory;
    }

    private List<OsvAffectedPackage> parseAffectedPackages(final JsonNode advisory) {

        List<OsvAffectedPackage> affectedPackages = new ArrayList<>();
        final ArrayNode affected = Jackson.optArray(advisory, "affected");
        if (affected != null) {
            for(int i=0; i<affected.size(); i++) {

                affectedPackages.addAll(parseAffectedPackageRange(affected.get(i)));
            }
        }
        return affectedPackages;
    }

    public List<OsvAffectedPackage> parseAffectedPackageRange(final JsonNode affected) {

        List<OsvAffectedPackage> osvAffectedPackageList = new ArrayList<>();
        final ArrayNode ranges = Jackson.optArray(affected, "ranges");
        final ArrayNode versions = Jackson.optArray(affected, "versions");
        if (ranges != null) {
            for (int j=0; j<ranges.size(); j++) {
                final JsonNode range = ranges.get(j);
                osvAffectedPackageList.addAll(parseVersionRanges(affected, range));
            }
        }
        // if ranges are not available or only commit hash range is available, look for versions
        if (osvAffectedPackageList.size() == 0 && versions != null && versions.size() > 0) {
            for (int j=0; j<versions.size(); j++) {
                OsvAffectedPackage vuln = createAffectedPackage(affected);
                vuln.setVersion(versions.get(j).asText());
                osvAffectedPackageList.add(vuln);
            }
        }
        // if no parsable range or version is available, add vulnerability without version
        else if (osvAffectedPackageList.size() == 0) {
            osvAffectedPackageList.add(createAffectedPackage(affected));
        }
        return osvAffectedPackageList;
    }

    private List<OsvAffectedPackage> parseVersionRanges(JsonNode vulnerability, JsonNode range) {
        final String rangeType = Jackson.optString(range, "type");
        if (!"ECOSYSTEM".equalsIgnoreCase(rangeType) && !"SEMVER".equalsIgnoreCase(rangeType)) {
            // We can't support ranges of type GIT for now, as evaluating them requires knowledge of
            // the entire Git history of a package. We don't have that, so there's no point in
            // ingesting this data.
            //
            // We're also implicitly excluding ranges of types that we don't yet know of.
            // This is a tradeoff of potentially missing new data vs. flooding our users'
            // database with junk data.
            return List.of();
        }

        final ArrayNode rangeEvents = Jackson.optArray(range, "events");
        if (rangeEvents == null) {
            return List.of();
        }

        final List<OsvAffectedPackage> affectedPackages = new ArrayList<>();

        for (int i = 0; i < rangeEvents.size(); i++) {
            JsonNode event = rangeEvents.get(i);

            final String introduced = Jackson.optString(event, "introduced");
            if (introduced == null) {
                // "introduced" is required for every range. But events are not guaranteed to be sorted,
                // it's merely a recommendation by the OSV specification.
                //
                // If events are not sorted, we have no way to tell what the correct order should be.
                // We make a tradeoff by assuming that ranges are sorted, and potentially skip ranges
                // that aren't.
                continue;
            }

            final OsvAffectedPackage affectedPackage = createAffectedPackage(vulnerability);
            affectedPackage.setLowerVersionRange(introduced);

            if (i + 1 < rangeEvents.size()) {
                event = rangeEvents.get(i + 1);
                final String fixed = Jackson.optString(event, "fixed");
                final String lastAffected = Jackson.optString(event, "last_affected");
                final String limit = Jackson.optString(event, "limit");

                if (fixed != null) {
                    affectedPackage.setUpperVersionRangeExcluding(fixed);
                    i++;
                } else if (lastAffected != null) {
                    affectedPackage.setUpperVersionRangeIncluding(lastAffected);
                    i++;
                } else if (limit != null) {
                    affectedPackage.setUpperVersionRangeExcluding(limit);
                    i++;
                }
            }

            // Special treatment for GitHub: https://github.com/github/advisory-database/issues/470
            final JsonNode databaseSpecific = Jackson.optNode(vulnerability, "database_specific");
            if (databaseSpecific != null
                    && affectedPackage.getUpperVersionRangeIncluding() == null
                    && affectedPackage.getUpperVersionRangeExcluding() == null) {
                final String lastAffectedRange = Jackson.optString(databaseSpecific, "last_known_affected_version_range");
                if (lastAffectedRange != null) {
                    if (lastAffectedRange.startsWith("<=")) {
                        affectedPackage.setUpperVersionRangeIncluding(lastAffectedRange.replaceFirst("<=", "").trim());
                    } else if (lastAffectedRange.startsWith("<")) {
                        affectedPackage.setUpperVersionRangeExcluding(lastAffectedRange.replaceAll("<", "").trim());
                    }
                }
            }

            affectedPackages.add(affectedPackage);
        }

        return affectedPackages;
    }

    private OsvAffectedPackage createAffectedPackage(JsonNode vulnerability) {

        OsvAffectedPackage osvAffectedPackage = new OsvAffectedPackage();
        final JsonNode affectedPackageJson = Jackson.optNode(vulnerability, "package");
        final JsonNode ecosystemSpecific = Jackson.optNode(vulnerability, "ecosystem_specific");
        final JsonNode databaseSpecific = Jackson.optNode(vulnerability, "database_specific");
        Severity ecosystemSeverity = parseEcosystemSeverity(ecosystemSpecific, databaseSpecific);
        osvAffectedPackage.setPackageName(Jackson.optString(affectedPackageJson, "name"));
        osvAffectedPackage.setPackageEcosystem(Jackson.optString(affectedPackageJson, "ecosystem"));
        osvAffectedPackage.setPurl(Jackson.optString(affectedPackageJson, "purl"));
        osvAffectedPackage.setSeverity(ecosystemSeverity);
        return osvAffectedPackage;
    }

    private Severity parseEcosystemSeverity(JsonNode ecosystemSpecific, JsonNode databaseSpecific) {

        String severity = null;

        if (databaseSpecific != null) {
            String cvssVector = Jackson.optString(databaseSpecific, "cvss");
            if (cvssVector != null) {
                Cvss cvss = Cvss.fromVector(cvssVector);
                Score score = cvss.calculateScore();
                severity = String.valueOf(normalizedCvssV3Score(score.getBaseScore()));
            }
        }

        if(severity == null && ecosystemSpecific != null) {
            severity = Jackson.optString(ecosystemSpecific, "severity");
        }

        if (severity != null) {
            if (severity.equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (severity.equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (severity.equalsIgnoreCase("MODERATE") || severity.equalsIgnoreCase("MEDIUM")) {
                return Severity.MEDIUM;
            } else if (severity.equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }
        return Severity.UNASSIGNED;
    }

    public String trimSummary(String summary) {
        final int MAX_LEN = 255;
        if(summary != null && summary.length() > 255) {
            return StringUtils.substring(summary, 0, MAX_LEN-2) + "..";
        }
        return summary;
    }
}