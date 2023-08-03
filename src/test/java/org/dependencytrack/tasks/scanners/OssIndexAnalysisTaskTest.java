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
package org.dependencytrack.tasks.scanners;

import alpine.model.IConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.assertj.core.api.SoftAssertions;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.OssIndexAnalysisEvent;
import org.dependencytrack.event.SnykAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentAnalysisCache;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.CweImporter;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.JsonBody;
import org.mockserver.verify.VerificationTimes;

import javax.jdo.Query;
import javax.json.Json;
import java.math.BigDecimal;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.SCANNER_OSSINDEX_ENABLED;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class OssIndexAnalysisTaskTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;
    private OssIndexAnalysisTask task;

    @BeforeClass
    public static void beforeClass() {
        NotificationService.getInstance().subscribe(new Subscription(SnykAnalysisTaskTest.NotificationSubscriber.class));
        mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @Before
    public void setUp() throws Exception {
        qm.createConfigProperty(
                SCANNER_OSSINDEX_ENABLED.getGroupName(),
                SCANNER_OSSINDEX_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "snyk"
        );
        qm.createConfigProperty(
                SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED.getGroupName(),
                SCANNER_OSSINDEX_ALIAS_SYNC_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "aliasSyncEnabled"
        );
        qm.createConfigProperty(
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getGroupName(),
                SCANNER_ANALYSIS_CACHE_VALIDITY_PERIOD.getPropertyName(),
                "86400",
                IConfigProperty.PropertyType.STRING,
                "cache"
        );

        task = new OssIndexAnalysisTask("http://localhost:1080");
    }

    @After
    public void tearDown() {
        mockServer.reset();
        NOTIFICATIONS.clear();
    }

    @AfterClass
    public static void afterClass() {
        mockServer.stop();
        NotificationService.getInstance().unsubscribe(new Subscription(SnykAnalysisTaskTest.NotificationSubscriber.class));
    }

    @Test
    public void testIsCapable() {
        final var asserts = new SoftAssertions();

        for (final Map.Entry<String, Boolean> test : Map.of(
                "pkg:maven/com.fasterxml.woodstox/woodstox-core", false, // Missing version
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0", true,
                "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", true
        ).entrySet()) {
            final var component = new Component();
            component.setPurl(test.getKey());
            asserts.assertThat(task.isCapable(component)).isEqualTo(test.getValue());
        }

        asserts.assertAll();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsCurrent() throws Exception {
        qm.updateComponentAnalysisCache(ComponentAnalysisCache.CacheType.VULNERABILITY, "http://localhost:1080",
                Vulnerability.Source.OSSINDEX.name(), "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz", new Date(),
                Json.createObjectBuilder()
                        .add("vulnIds", Json.createArrayBuilder().add(123))
                        .build());

        assertThat(task.shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isFalse();
    }

    @Test
    public void testShouldAnalyzeWhenCacheIsNotCurrent() throws Exception {
        assertThat(task.shouldAnalyze(new PackageURL("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz"))).isTrue();
    }

    @Test
    public void testAnalyzeWithRateLimiting() throws Exception {
        new CweImporter().processCweDefinitions();

        mockServer
                .when(request(), Times.exactly(2))
                .respond(response().withStatusCode(429));

        mockServer
                .when(request()
                        .withMethod("POST")
                        .withBody(JsonBody.json("""
                                {
                                  "coordinates": [
                                    "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
                                  ]
                                }
                                """)))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.ossindex.component-report.v1+json")
                        .withBody("""
                                [
                                  {
                                    "coordinates": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                                    "description": "General data-binding functionality for Jackson: works on core streaming API",
                                    "reference": "https://ossindex.sonatype.org/component/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                                    "vulnerabilities": [
                                      {
                                        "id": "CVE-2020-36518",
                                        "displayName": "CVE-2020-36518",
                                        "title": "[CVE-2020-36518] CWE-787: Out-of-bounds Write",
                                        "description": "jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.\\n\\nSonatype's research suggests that this CVE's details differ from those defined at NVD. See https://ossindex.sonatype.org/vulnerability/CVE-2020-36518 for details",
                                        "cvssScore": 7.5,
                                        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                        "cwe": "CWE-787",
                                        "cve": "CVE-2020-36518",
                                        "reference": "https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                                        "externalReferences": [
                                          "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518",
                                          "https://github.com/FasterXML/jackson-databind/issues/2816"
                                        ]
                                      }
                                    ]
                                  }
                                ]
                                """));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.13.1");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
        component = qm.createComponent(component, false);

        task.inform(new OssIndexAnalysisEvent(component));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).satisfiesExactly(
                vuln -> {
                    assertThat(vuln.getVulnId()).isEqualTo("CVE-2020-36518");
                    assertThat(vuln.getSource()).isEqualTo("NVD");
                    assertThat(vuln.getTitle()).isNull();
                    assertThat(vuln.getDescription()).isEqualTo("""
                            jackson-databind before 2.13.0 allows a Java StackOverflow exception and denial of service via a large depth of nested objects.
                                                    
                            Sonatype's research suggests that this CVE's details differ from those defined at NVD. See https://ossindex.sonatype.org/vulnerability/CVE-2020-36518 for details""");
                    assertThat(vuln.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
                    assertThat(vuln.getCvssV3BaseScore()).isEqualTo(new BigDecimal("7.5"));
                    assertThat(vuln.getCvssV3ExploitabilitySubScore()).isNotNull();
                    assertThat(vuln.getCvssV3ImpactSubScore()).isNotNull();
                    assertThat(vuln.getCwes()).containsOnly(787);
                    assertThat(vuln.getReferences()).isEqualTo("""
                            * [https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0](https://ossindex.sonatype.org/vulnerability/CVE-2020-36518?component-type=maven&component-name=com.fasterxml.jackson.core%2Fjackson-databind&utm_source=mozilla&utm_medium=integration&utm_content=5.0)
                            * [http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-36518)
                            * [https://github.com/FasterXML/jackson-databind/issues/2816](https://github.com/FasterXML/jackson-databind/issues/2816)""");
                }
        );

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).satisfiesExactly(
                entry -> {
                    assertThat(entry.getTargetHost()).isEqualTo("http://localhost:1080");
                    assertThat(entry.getTarget()).isEqualTo("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
                    assertThat(entry.getResult()).containsEntry("vulnIds",
                            Json.createArrayBuilder(vulnerabilities.stream().map(Vulnerability::getId).toList()).build());
                }
        );

        mockServer.verify(request(), VerificationTimes.exactly(3));
    }

    @Test
    public void testAnalyzeWithNoIssues() {
        mockServer
                .when(request()
                        .withMethod("POST")
                        .withBody(JsonBody.json("""
                                {
                                  "coordinates": [
                                    "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
                                  ]
                                }
                                """)))
                .respond(response()
                        .withStatusCode(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.ossindex.component-report.v1+json")
                        .withBody("""
                                [
                                  {
                                    "coordinates": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
                                    "description": "General data-binding functionality for Jackson: works on core streaming API",
                                    "reference": "https://ossindex.sonatype.org/component/pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                                    "vulnerabilities": []
                                  }
                                ]
                                """));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.13.1");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
        component = qm.createComponent(component, false);

        task.inform(new OssIndexAnalysisEvent(component));

        assertThat(qm.getAllVulnerabilities(component)).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).satisfiesExactly(
                entry -> {
                    assertThat(entry.getTarget()).isEqualTo("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1");
                    assertThat(entry.getResult()).isNull();
                }
        );
    }

    @Test
    public void testAnalyzeWithError() {
        mockServer
                .when(request()
                        .withMethod("GET")
                        .withPath("/rest/orgs/orgid/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0/issues")
                        .withQueryStringParameter("version", "version"))
                .respond(response()
                        .withStatusCode(400)
                        .withHeader(HttpHeaders.CONTENT_TYPE, "application/vnd.api+json")
                        .withBody("""
                                {
                                  "jsonapi": {
                                    "version": "1.0"
                                  },
                                  "errors": [
                                    {
                                      "id": "0f12fd75-c80a-4c15-929b-f7794eb3dd4f",
                                      "links": {
                                        "about": "https://docs.snyk.io/more-info/error-catalog#snyk-ossi-2010-invalid-purl-has-been-provided"
                                      },
                                      "status": "400",
                                      "code": "SNYK-OSSI-2010",
                                      "title": "Invalid PURL has been provided",
                                      "detail": "pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0%",
                                      "source": {
                                        "pointer": "/orgs/0d581750-c5d7-4acf-9ff9-4a5bae31cbf1/packages/pkg%3Amaven%2Fcom.fasterxml.woodstox%2Fwoodstox-core%405.0.0%25/issues"
                                      },
                                      "meta": {
                                        "links": [
                                          "https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst"
                                        ]
                                      }
                                    }
                                  ]
                                }
                                """));

        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, null, false);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.woodstox");
        component.setName("woodstox-core");
        component.setVersion("5.0.0");
        component.setPurl("pkg:maven/com.fasterxml.woodstox/woodstox-core@5.0.0?foo=bar#baz");
        component = qm.createComponent(component, false);

        new SnykAnalysisTask().inform(new SnykAnalysisEvent(List.of(component)));

        final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
        assertThat(vulnerabilities).hasSize(0);

        final Query<ComponentAnalysisCache> cacheQuery = qm.getPersistenceManager().newQuery(ComponentAnalysisCache.class);
        assertThat(cacheQuery.executeList()).isEmpty();
    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

}