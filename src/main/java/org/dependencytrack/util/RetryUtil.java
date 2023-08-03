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
package org.dependencytrack.util;

import alpine.common.logging.Logger;
import io.github.resilience4j.core.EventConsumer;
import io.github.resilience4j.core.EventPublisher;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.event.RetryEvent;
import io.github.resilience4j.retry.event.RetryOnErrorEvent;
import io.github.resilience4j.retry.event.RetryOnRetryEvent;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.Closeable;
import java.util.Collection;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

public final class RetryUtil {

    /**
     * Ensure that a {@link Closeable} result from a previous retry attempt is closed before
     * executing the next attempt. When closing fails, log the exception as warning with {@code logger}.
     *
     * @param logger The {@link Logger} to log warnings with
     * @param <T>    Type of the {@link Closeable} result
     * @return A {@link BiConsumer} to use with {@link RetryConfig.Builder#consumeResultBeforeRetryAttempt(BiConsumer)}
     */
    public static <T extends Closeable> BiConsumer<Integer, T> maybeClosePreviousResult(final Logger logger) {
        return (attempt, closeable) -> {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (Exception e) {
                    logger.warn("Failed to close previous result before retry attempt #%d".formatted(attempt), e);
                }
            }
        };
    }

    /**
     * Handle {@link RetryEvent}s by logging them with a given {@link Logger}.
     *
     * @param logger The {@link Logger} to use
     * @param <T>    Type of the {@link RetryEvent}
     * @return An {@link EventConsumer} to use with {@link EventPublisher#onEvent(EventConsumer)}
     */
    public static <T extends RetryEvent> EventConsumer<T> logRetryEventWith(final Logger logger) {
        return event -> {
            if (event instanceof final RetryOnRetryEvent retryEvent) {
                final var message = "Encountered retryable error for %s; Will execute retry #%d in %s"
                        .formatted(event.getName(), event.getNumberOfRetryAttempts(), retryEvent.getWaitInterval());
                if (event.getLastThrowable() != null) {
                    logger.warn(message, event.getLastThrowable());
                } else {
                    logger.warn(message);
                }
            } else if (event instanceof final RetryOnErrorEvent errorEvent) {
                final var message = "Max retry attempts exceeded for %s after %d attempts"
                        .formatted(errorEvent.getName(), errorEvent.getNumberOfRetryAttempts());
                if (errorEvent.getLastThrowable() != null) {
                    logger.error(message, errorEvent.getLastThrowable());
                } else {
                    logger.error(message);
                }
            }
        };
    }

    /**
     * Determine if a {@link Throwable} has a root cause matching any of the given {@code causeClasses}.
     *
     * @param causeClasses {@link Class}es of {@link Throwable}s to check for
     * @return A {@link Predicate} to use with {@link RetryConfig.Builder#retryOnException(Predicate)}
     */
    public static Predicate<Throwable> withRootCauseAnyOf(final Collection<Class<? extends Throwable>> causeClasses) {
        return throwable -> {
            final Throwable rootCause = ExceptionUtils.getRootCause(throwable);
            return causeClasses.stream()
                    .anyMatch(causeClass -> causeClass.isAssignableFrom(rootCause.getClass()));
        };
    }

}
