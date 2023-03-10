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
package org.dependencytrack.common;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import org.apache.http.client.methods.CloseableHttpResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Helper class wrapping a Jackson {@link ObjectMapper} and providing various utility methods.
 *
 * @since 4.8.0
 */
public final class Jackson {

    private static final ObjectMapper OBJECT_MAPPER;

    static {
        OBJECT_MAPPER = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setDateFormat(new SimpleDateFormat("HH:mm:ss.SSSZ"));
    }

    private Jackson() {
    }

    public static ObjectReader objectReader() {
        return OBJECT_MAPPER.reader();
    }

    public static ObjectWriter objectWriter() {
        return OBJECT_MAPPER.writer();
    }

    public static JsonNodeFactory nodeFactory() {
        return OBJECT_MAPPER.getNodeFactory();
    }

    public static ArrayNode newArray() {
        return nodeFactory().arrayNode();
    }

    public static ObjectNode newObject() {
        return nodeFactory().objectNode();
    }

    public static JsonNode readString(final String string) {
        return readString(string, JsonNode.class);
    }

    public static <T> T readString(final String string, Class<T> clazz) {
        try {
            return objectReader().readValue(string, clazz);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static JsonNode readHttpResponse(final CloseableHttpResponse response) throws IOException {
        return readHttpResponse(response, JsonNode.class);
    }

    public static <T> T readHttpResponse(final CloseableHttpResponse response, final Class<T> clazz) throws IOException {
        if ((response != null) && (response.getEntity().getContent() != null)) {
            try (final InputStream entityInputStream = response.getEntity().getContent()) {
                return objectReader().readValue(entityInputStream, clazz);
            }
        }
        return null;
    }

    public static ArrayNode asArray(final JsonNode jsonNode, final String fieldName) {
        final JsonNode arrayNode = jsonNode.get(fieldName);
        if (arrayNode == null || !arrayNode.isArray()) {
            return nodeFactory().arrayNode();
        }

        return (ArrayNode) arrayNode;
    }

    public static String optString(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.asText();
    }

    public static String optString(final JsonNode jsonNode, final int index) {
        final var field = jsonNode.get(index);
        return field == null || field.isNull() ? null : field.asText();
    }

    public static Integer optInt(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.asInt();
    }

    public static Number optLong(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.asLong();
    }

    public static Double optDouble(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.asDouble();
    }

    public static BigDecimal optBigDecimal(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.decimalValue();
    }

    public static Boolean optBoolean(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field.asBoolean();
    }

    public static JsonNode optNode(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : field;
    }

    public static JsonNode optNode(final JsonNode jsonNode, final int index) {
        final var field = jsonNode.get(index);
        return field == null || field.isNull() ? null : field;
    }

    public static ArrayNode optArray(final JsonNode jsonNode, final String fieldName) {
        final var field = jsonNode.get(fieldName);
        return field == null || field.isNull() ? null : (ArrayNode)field;
    }

    /**
     * An alternative to {@link JsonNode#toString()} that makes use of the customized {@link ObjectMapper}.
     *
     * @param value The value to serialize
     * @return The serialized valued
     * @throws RuntimeException When serialization failed
     */
    public static <T extends JsonNode> String toString(final T value) {
        try {
            return objectWriter().writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
