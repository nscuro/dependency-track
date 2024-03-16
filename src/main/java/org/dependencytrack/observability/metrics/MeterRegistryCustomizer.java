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
package org.dependencytrack.observability.metrics;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig;

/**
 * @since 4.11.0
 */
public class MeterRegistryCustomizer implements alpine.common.metrics.MeterRegistryCustomizer {

    @Override
    public void accept(final MeterRegistry meterRegistry) {
        meterRegistry.config().meterFilter(new MeterFilter() {

            @Override
            public DistributionStatisticConfig configure(final Meter.Id id, final DistributionStatisticConfig config) {
                if (id.getType() == Meter.Type.TIMER && id.getName().startsWith("alpine_event_processing")) {
                    return DistributionStatisticConfig.builder()
                            .percentiles(0.5, 0.75, 0.9, 0.95, 0.99)
                            .percentilesHistogram(true)
                            .build()
                            .merge(config);
                }

                return MeterFilter.super.configure(id, config);
            }
            
        });
    }

}
