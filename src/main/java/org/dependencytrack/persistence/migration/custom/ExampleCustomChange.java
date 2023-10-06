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
package org.dependencytrack.persistence.migration.custom;

import alpine.common.logging.Logger;
import liquibase.change.custom.CustomTaskChange;
import liquibase.database.Database;
import liquibase.exception.CustomChangeException;
import liquibase.exception.SetupException;
import liquibase.exception.ValidationErrors;
import liquibase.resource.ResourceAccessor;

public class ExampleCustomChange implements CustomTaskChange {

    private static final Logger LOGGER = Logger.getLogger(ExampleCustomChange.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void setUp() throws SetupException {
        LOGGER.info("setUp");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void execute(final Database database) throws CustomChangeException {
        LOGGER.info("execute");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getConfirmationMessage() {
        LOGGER.info("getConfirmationMessage");
        return "foo";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setFileOpener(final ResourceAccessor resourceAccessor) {
        LOGGER.info("setFileOpener");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationErrors validate(final Database database) {
        LOGGER.info("validate");
        return null;
    }

}
