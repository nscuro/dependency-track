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
package org.dependencytrack.persistence.migration;

import alpine.Config;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import liquibase.Liquibase;
import liquibase.Scope;
import liquibase.command.CommandScope;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionCommandStep;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import java.util.HashMap;

public class MigrationInitializer implements ServletContextListener {

    private final Config config;

    @SuppressWarnings("unused")
    public MigrationInitializer() {
        this(Config.getInstance());
    }

    MigrationInitializer(final Config config) {
        this.config = config;
    }

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        final var liquibaseConfig = new HashMap<String, Object>();

        try (final HikariDataSource dataSource = createDataSource()) {
            Scope.child(liquibaseConfig, () -> {
                final Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(dataSource.getConnection()));
                final var liquibase = new Liquibase("migration/changelog-main.xml", new ClassLoaderResourceAccessor(), database);

                final var updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME);
                updateCommand.addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, liquibase.getDatabase());
                updateCommand.addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, liquibase.getChangeLogFile());
                updateCommand.execute();
            });
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute migration", e);
        }
    }

    private HikariDataSource createDataSource() {
        final var hikariCfg = new HikariConfig();
        hikariCfg.setJdbcUrl(config.getProperty(Config.AlpineKey.DATABASE_URL));
        hikariCfg.setDriverClassName(config.getProperty(Config.AlpineKey.DATABASE_DRIVER));
        hikariCfg.setUsername(config.getProperty(Config.AlpineKey.DATABASE_USERNAME));
        hikariCfg.setPassword(config.getProperty(Config.AlpineKey.DATABASE_PASSWORD));
        hikariCfg.setMaximumPoolSize(1);
        hikariCfg.setMinimumIdle(1);

        return new HikariDataSource(hikariCfg);
    }

}
