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
package org.dependencytrack.resources.v1;

import alpine.common.logging.Logger;
import alpine.server.auth.AuthenticationNotRequired;
import alpine.server.resources.AlpineResource;
import io.github.jeremylong.openvulnerability.client.nvd.CveApiJson20;
import org.dependencytrack.util.LuceneNvdCveApiCacheManager;
import org.dependencytrack.util.LuceneNvdCveApiCacheManager.ApiParameters;
import org.dependencytrack.util.LuceneNvdCveApiCacheManager.Mode;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Path("/v1/mirror")
public class MirrorResource extends AlpineResource {

    private static final Logger LOGGER = Logger.getLogger(MirrorResource.class);
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssX");

    @GET
    @Path("/nvd/cves/2.0")
    @Produces(MediaType.APPLICATION_JSON)
    @AuthenticationNotRequired
    public Response getNvdCvesFromCache(@QueryParam("lastModStartDate") final String lastModStartDate,
                                        @QueryParam("lastModEndDate") final String lastModEndDate,
                                        @QueryParam("resultsPerPage") final Integer resultsPerPage,
                                        @QueryParam("startIndex") final Integer startIndex) {
        final ZonedDateTime parsedLastModStartDate = maybeParseDate(lastModStartDate);
        final ZonedDateTime parsedLastModEndDate = maybeParseDate(lastModEndDate);

        // If filtering by the last modified date, both lastModStartDate and lastModEndDate are required.
        if (parsedLastModStartDate != null ^ parsedLastModEndDate != null) {
            throw new IllegalArgumentException("Either both lastModStartDate and lastModEndDate must be provided, or none of them.");
        } else if (parsedLastModStartDate != null && parsedLastModEndDate != null) {
            // The maximum allowable range when using any date range parameters is 120 consecutive days.
            if (Duration.between(parsedLastModStartDate, parsedLastModEndDate).compareTo(Duration.ofDays(120)) > 0) {
                throw new IllegalArgumentException("lastModStartDate and lastModEndDate are more than 120 days apart.");
            }
        }

        try (final LuceneNvdCveApiCacheManager cacheManager = LuceneNvdCveApiCacheManager.create(Mode.READ_ONLY)) {
            final CveApiJson20 json = cacheManager.getApiResponseFromCache(new ApiParameters()
                    .withLastModStartDate(parsedLastModStartDate)
                    .withLastModEndDate(parsedLastModEndDate)
                    .withResultsPerPage(resultsPerPage)
                    .withStartIndex(startIndex));
            return Response.ok(json).build();
        } catch (IOException e) {
            LOGGER.error("Failed to populate CVE API response from cache", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    private static ZonedDateTime maybeParseDate(final String dateString) {
        return dateString != null
                ? ZonedDateTime.parse(dateString, DATE_TIME_FORMATTER)
                : null;
    }

}
