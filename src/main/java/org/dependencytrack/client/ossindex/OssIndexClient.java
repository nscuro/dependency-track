package org.dependencytrack.client.ossindex;

import alpine.common.logging.Logger;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import kong.unirest.GenericType;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.common.UnirestFactory;

import java.time.Duration;
import java.util.Collection;
import java.util.List;

public class OssIndexClient {

    private static final Logger LOGGER = Logger.getLogger(OssIndexClient.class);
    private static final String DEFAULT_BASE_URL = "https://ossindex.sonatype.org";
    private static final RetryConfig RETRY_CONFIG = RetryConfig.custom()
            .retryExceptions(IllegalStateException.class)
            .waitDuration(Duration.ofSeconds(2))
            .maxAttempts(3)
            .build();

    private final String apiBaseUrl;
    private final String apiUsername;
    private final String apiToken;

    public OssIndexClient(final String apiUsername, final String apiToken) {
        this(DEFAULT_BASE_URL, apiUsername, apiToken);
    }

    OssIndexClient(final String apiBaseUrl, final String apiUsername, final String apiToken) {
        this.apiBaseUrl = apiBaseUrl;
        this.apiUsername = apiUsername;
        this.apiToken = apiToken;
    }

    public List<ComponentReport> getComponentReports(final Collection<String> coordinates) {
        final HttpRequestWithBody request = UnirestFactory.getUnirestInstance()
                .post(apiBaseUrl + "/api/v3/component-report")
                .header(HttpHeaders.ACCEPT, "application/vnd.ossindex.component-report.v1+json")
                .header(HttpHeaders.CONTENT_TYPE, "application/vnd.ossindex.component-report-request.v1+json")
                .header(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
        if (StringUtils.isNotBlank(apiUsername) && StringUtils.isNotBlank(apiToken)) {
            request.basicAuth(apiUsername, apiToken);
        }

        return Retry.of("getComponentReports", RETRY_CONFIG).executeSupplier(() -> {
            final HttpResponse<List<ComponentReport>> response = request
                    .body(new ComponentReportRequest(coordinates))
                    .asObject(new GenericType<>() {
                    });

            if (HttpStatus.TOO_MANY_REQUESTS == response.getStatus()
                    || HttpStatus.SERVICE_UNAVAILABLE == response.getStatus()) {
                throw new IllegalStateException();
            } else if (!response.isSuccess()) {
                throw new IllegalArgumentException("Foo: " + response.getStatus());
            }

            return response.getBody();
        });
    }

    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

}
