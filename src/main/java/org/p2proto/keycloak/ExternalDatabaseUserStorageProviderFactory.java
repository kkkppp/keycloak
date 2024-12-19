package org.p2proto.keycloak;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ExternalDatabaseUserStorageProviderFactory implements UserStorageProviderFactory<ExternalDatabaseUserStorageProvider> {

    private static final Logger logger = LoggerFactory.getLogger(ExternalDatabaseUserStorageProviderFactory.class);

    private static final String NO_DB_URL = "DB_URL environment variable is not set";
    private static final String NO_DB_USERNAME = "DB_USERNAME environment variable is not set";
    private static final String NO_DB_PASSWORD = "DB_PASSWORD environment variable is not set";

    private HikariDataSource dataSource;

    @Override
    public void init(Config.Scope config) {
        UserStorageProviderFactory.super.init(config);
        try {
            HikariConfig hikariConfig = new HikariConfig();
            hikariConfig.setJdbcUrl(getDbUrl());
            hikariConfig.setUsername(getDbUsername());
            hikariConfig.setPassword(getDbPassword());
            hikariConfig.setMaximumPoolSize(10);
            hikariConfig.setMinimumIdle(2);
            hikariConfig.setIdleTimeout(30000);
            hikariConfig.setConnectionTimeout(30000);
            hikariConfig.setPoolName("KeycloakUserStoragePool");
            this.dataSource = new HikariDataSource(hikariConfig);
        } catch (IllegalStateException e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    @Override
    public ExternalDatabaseUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        return new ExternalDatabaseUserStorageProvider(session, model, dataSource);
    }

    @Override
    public String getId() {
        return "p2-db-user-storage";
    }

    private String getDbUrl() {
        String dbUrl = System.getenv("KC_DB_URL");
        if (dbUrl == null || dbUrl.isEmpty()) {
            throw new IllegalStateException(NO_DB_URL);
        }
        return dbUrl;
    }

    private String getDbUsername() {
        String dbUsername = System.getenv("KC_DB_USERNAME");
        if (dbUsername == null || dbUsername.isEmpty()) {
            throw new IllegalStateException(NO_DB_USERNAME);
        }
        return dbUsername;
    }

    private String getDbPassword() {
        String dbPasswordFile = System.getenv("KC_DB_PASSWORD_FILE");
        if (dbPasswordFile != null && !dbPasswordFile.isEmpty()) {
            try {
                return new String(Files.readAllBytes(Paths.get(dbPasswordFile))).trim();
            } catch (IOException e) {
                throw new RuntimeException("Failed to read database password from file", e);
            }
        } else {
            String dbPassword = System.getenv("KC_DB_PASSWORD");
            if (dbPassword == null || dbPassword.isEmpty()) {
                throw new IllegalStateException(NO_DB_PASSWORD);
            }
            return dbPassword;
        }
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            new Exception().printStackTrace();
            dataSource.close();
            logger.info("HikariCP DataSource closed");
        }
    }
}
