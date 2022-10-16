package org.dependencytrack.client.ossindex;

import java.util.Collection;

public record ComponentReportRequest(Collection<String> coordinates) {
}
