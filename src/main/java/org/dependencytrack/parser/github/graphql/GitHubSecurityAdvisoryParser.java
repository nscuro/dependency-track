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
package org.dependencytrack.parser.github.graphql;

import static org.dependencytrack.util.JsonUtil.jsonStringToTimestamp;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;
import org.dependencytrack.common.Jackson;
import org.dependencytrack.parser.github.graphql.model.GitHubSecurityAdvisory;
import org.dependencytrack.parser.github.graphql.model.GitHubVulnerability;
import org.dependencytrack.parser.github.graphql.model.PageableList;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

public class GitHubSecurityAdvisoryParser {

    public PageableList parse(final JsonNode object) {
        final PageableList pageableList = new PageableList();
        final List<GitHubSecurityAdvisory> advisories = new ArrayList<>();
        final JsonNode data = object.get("data");
        if (data != null) {
            final JsonNode securityAdvisories = data.get("securityAdvisories");
            if (securityAdvisories != null) {
                final ArrayNode securityAdvisoriesNodes = Jackson.asArray(securityAdvisories, "nodes");
                if (securityAdvisoriesNodes != null) {
                    for (int i = 0; i < securityAdvisoriesNodes.size(); i++) {
                        final JsonNode securityAdvisory = securityAdvisoriesNodes.get(i);
                        final GitHubSecurityAdvisory advisory = parseSecurityAdvisory(securityAdvisory);
                        advisories.add(advisory);
                    }
                }
                pageableList.setTotalCount(Jackson.optInt(securityAdvisories,"totalCount"));
                final JsonNode pageInfo = securityAdvisories.get("pageInfo");
                if (pageInfo != null) {
                    pageableList.setHasNextPage(Jackson.optBoolean(pageInfo,"hasNextPage"));
                    pageableList.setHasPreviousPage(Jackson.optBoolean(pageInfo,"hasPreviousPage"));
                    pageableList.setStartCursor(Jackson.optString(pageInfo,"startCursor"));
                    pageableList.setEndCursor(Jackson.optString(pageInfo,"endCursor"));
                }
            }
        }
        pageableList.setAdvisories(advisories);
        return pageableList;
    }

    private GitHubSecurityAdvisory parseSecurityAdvisory(final JsonNode object) {
        final GitHubSecurityAdvisory advisory = new GitHubSecurityAdvisory();
        advisory.setDatabaseId(object.get("databaseId").asInt());
        advisory.setDescription(Jackson.optString(object,"description"));
        advisory.setGhsaId(Jackson.optString(object,"ghsaId"));
        advisory.setId(Jackson.optString(object,"id"));
        advisory.setNotificationsPermalink(Jackson.optString(object,"notificationsPermalink"));
        advisory.setOrigin(Jackson.optString(object,"origin"));
        advisory.setPermalink(Jackson.optString(object,"permalink"));
        advisory.setSeverity(Jackson.optString(object,"severity"));
        advisory.setSummary(Jackson.optString(object,"summary"));
        advisory.setPublishedAt(jsonStringToTimestamp(Jackson.optString(object,"publishedAt")));
        advisory.setUpdatedAt(jsonStringToTimestamp(Jackson.optString(object,"updatedAt")));
        advisory.setWithdrawnAt(jsonStringToTimestamp(Jackson.optString(object,"withdrawnAt")));

        final ArrayNode identifiers = Jackson.asArray(object,"identifiers");
        if (identifiers != null) {
            for (int i=0; i<identifiers.size(); i++) {
                final JsonNode identifier = identifiers.get(i);
                final String type = Jackson.optString(identifier,"type");
                final String value = Jackson.optString(identifier,"value");
                if (type != null && value != null) {
                    final Pair<String, String> pair = Pair.of(type, value);
                    advisory.addIdentifier(pair);
                }
            }
        }

        final ArrayNode references = Jackson.asArray(object,"references");
        if (references != null) {
            for (int i=0; i<references.size(); i++) {
                final String url = (Jackson.optString(references.get(i), "url"));
                if (url != null) {
                    advisory.addReference(url);
                }
            }
        }

        final JsonNode cvss = Jackson.optNode(object,"cvss");
        if (cvss != null) {
            advisory.setCvssScore(Jackson.optInt(cvss, "score"));
            advisory.setCvssVector(Jackson.optString(cvss,"score"));
        }

        final JsonNode cwes = Jackson.optNode(object,"cwes");
        if (cwes != null) {
            final ArrayNode edges = Jackson.asArray(cwes,"edges");
            if (edges != null) {
                for (int i = 0; i < edges.size(); i++) {
                    final JsonNode edge = edges.get(i);
                    if (edge != null) {
                        final JsonNode node = Jackson.optNode(edge,"node");
                        if (node != null) {
                            final String cweId = Jackson.optString(node,"cweId");
                            if (cweId != null) {
                                advisory.addCwe(cweId);
                            }
                        }
                    }
                }
            }
        }
        final List<GitHubVulnerability> vulnerabilities = parseVulnerabilities(object);
        advisory.setVulnerabilities(vulnerabilities);
        return advisory;
    }

    private List<GitHubVulnerability> parseVulnerabilities(final JsonNode object) {
        final List<GitHubVulnerability> vulnerabilities = new ArrayList<>();
        final JsonNode vs = Jackson.optNode(object,"vulnerabilities");
        if (vs != null) {
            final ArrayNode edges = Jackson.asArray(vs,"edges");
            if (edges != null) {
                for (int i=0; i<edges.size(); i++) {
                    final JsonNode node = Jackson.optNode(edges.get(i), "node");
                    if (node != null) {
                        GitHubVulnerability vulnerability = parseVulnerability(node);
                        vulnerabilities.add(vulnerability);
                    }
                }
            }
        }
        return vulnerabilities;
    }

    private GitHubVulnerability parseVulnerability(final JsonNode object) {
        final GitHubVulnerability vulnerability = new GitHubVulnerability();
        vulnerability.setSeverity(Jackson.optString(object,"severity"));
        vulnerability.setUpdatedAt(jsonStringToTimestamp(Jackson.optString(object,"updatedAt")));
        final JsonNode firstPatchedVersion = Jackson.optNode(object,"firstPatchedVersion");
        if (firstPatchedVersion != null) {
            vulnerability.setFirstPatchedVersionIdentifier(Jackson.optString(firstPatchedVersion,"identifier"));
        }
        vulnerability.setVulnerableVersionRange(Jackson.optString(object,"vulnerableVersionRange"));
        final JsonNode packageObject = Jackson.optNode(object,"package");
        if (packageObject != null) {
            vulnerability.setPackageEcosystem(Jackson.optString(packageObject,"ecosystem"));
            vulnerability.setPackageName(Jackson.optString(packageObject,"name"));
        }
        return vulnerability;
    }
}
