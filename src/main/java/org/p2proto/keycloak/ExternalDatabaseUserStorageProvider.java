package org.p2proto.keycloak;

import com.zaxxer.hikari.HikariDataSource;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class ExternalDatabaseUserStorageProvider implements
        UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        UserQueryProvider {

    private static final Logger logger = LoggerFactory.getLogger(ExternalDatabaseUserStorageProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;
    private final HikariDataSource dataSource;

    public ExternalDatabaseUserStorageProvider(KeycloakSession session, ComponentModel model, HikariDataSource dataSource) {
        this.session = session;
        this.model = model;
        this.dataSource = dataSource;
    }


    public Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        logger.info("isValid, user = " + user);
        if (!(credentialInput instanceof UserCredentialModel)) {
            return false;
        }

        if (!supportsCredentialType(credentialInput.getType())) {
            return false;
        }

        String username = user.getUsername();
        String password = credentialInput.getChallengeResponse();

        try (Connection connection = getConnection()) {
            String sql = "SELECT password_hash FROM platform.users WHERE username = ?";
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        String storedHash = rs.getString("password_hash");
                        return verifyPassword(password, storedHash);
                    } else {
                        return false; // User not found
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Error validating credentials for user: {}", username, e);
            return false;
        }
    }

    private boolean verifyPassword(String password, String storedHash) {
        return BCrypt.checkpw(password, storedHash);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        logger.info("getUserById, id = " + id);
        //new Exception().printStackTrace();

        String uuid = extractExternalUserId(id);
        if (uuid == null) {
            // If we failed to extract a valid UUID, just return null
            return null;
        }

        try (Connection connection = getConnection()) {
            String sql = "SELECT id, username, email, first_name, last_name FROM platform.users WHERE id = ?::uuid";
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, uuid);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return mapUser(rs, realm);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by ID: {}", id, e);
        }

        return null;
    }

    /**
     * Extract the external user UUID from a Keycloak user ID.
     * The expected format is "f:<componentId>:<externalId>".
     * If the format doesn't match or the component doesn't match this provider, return null.
     */
    private String extractExternalUserId(String keycloakUserId) {
        if (keycloakUserId == null) {
            logger.warn("User ID is null");
            return null;
        }

        String[] parts = keycloakUserId.split(":");
        if (parts.length != 3 || !"f".equals(parts[0])) {
            logger.warn("Invalid user ID format: " + keycloakUserId);
            return null;
        }

        String componentId = parts[1];
        String externalId = parts[2];

        // Verify that this user ID belongs to this provider
        if (!model.getId().equals(componentId)) {
            logger.warn("User ID " + keycloakUserId + " does not match this provider's component ID " + model.getId());
            return null;
        }

        return externalId;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.info("getUserByName, name = " + username);
        //new Exception().printStackTrace();
        try (Connection connection = getConnection()) {
            String sql = "SELECT id, username, email, first_name, last_name FROM platform.users WHERE username = ?";
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return mapUser(rs, realm);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by username: {}", username, e);
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.info("getUserByEmail, email = " + email);
        try (Connection connection = getConnection()) {
            String sql = "SELECT id, username, email, first_name, last_name FROM platform.users WHERE email = ?";
            try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                stmt.setString(1, email);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return mapUser(rs, realm);
                    }
                }
            }
        } catch (SQLException e) {
            logger.error("Error fetching user by email: {}", email, e);
        }
        return null;
    }

    private UserModel mapUser(ResultSet rs, RealmModel realm) throws SQLException {
        String id = rs.getString("id");
        String username = rs.getString("username");
        String email = rs.getString("email");
        String firstName = rs.getString("first_name");
        String lastName = rs.getString("last_name");

        return new AbstractUserAdapterFederatedStorage(session, realm, model) {
            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public void setUsername(String username) {
                // Implement if needed
            }

            @Override
            public String getEmail() {
                return email;
            }

            @Override
            public void setEmail(String email) {
                // Implement if needed
            }

            @Override
            public String getFirstName() {
                return firstName;
            }

            @Override
            public void setFirstName(String firstName) {
                // Implement if needed
            }

            @Override
            public String getLastName() {
                return lastName;
            }

            @Override
            public void setLastName(String lastName) {
                // Implement if needed
            }

            @Override
            public String getId() {
                return "f:"+model.getId()+":"+id;
            }
        };
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        logger.info("searchForUserStream, params = " + params);
        List<UserModel> users = new ArrayList<>();

        StringBuilder sqlBuilder = new StringBuilder("SELECT id, username, email, first_name, last_name FROM users WHERE 1=1");
        List<Object> parameters = new ArrayList<>();

        boolean exact = Boolean.parseBoolean(params.getOrDefault(UserModel.EXACT, "false"));

        if (params.containsKey(UserModel.SEARCH)) {
            // Handle the SEARCH parameter
            String search = params.get(UserModel.SEARCH).trim();

            // If search is "*", return all users without additional filters
            if (!"*".equals(search)) {
                String[] searchTerms = search.split("\\s+");
                sqlBuilder.append(" AND (");
                List<String> searchConditions = new ArrayList<>();
                for (String term : searchTerms) {
                    String condition = "(LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ?)";
                    searchConditions.add(condition);
                    String likeTerm = "%" + term.toLowerCase() + "%";
                    parameters.add(likeTerm);
                    parameters.add(likeTerm);
                    parameters.add(likeTerm);
                    parameters.add(likeTerm);
                }
                sqlBuilder.append(String.join(" OR ", searchConditions));
                sqlBuilder.append(")");
            }
        } else {
            // Handle individual parameters when SEARCH is not present

            if (params.containsKey(UserModel.USERNAME)) {
                String username = params.get(UserModel.USERNAME);
                sqlBuilder.append(" AND ");
                if (exact) {
                    sqlBuilder.append("LOWER(username) = ?");
                    parameters.add(username.toLowerCase());
                } else {
                    sqlBuilder.append("LOWER(username) LIKE ?");
                    parameters.add("%" + username.toLowerCase() + "%");
                }
            }

            if (params.containsKey(UserModel.EMAIL)) {
                String email = params.get(UserModel.EMAIL);
                sqlBuilder.append(" AND ");
                if (exact) {
                    sqlBuilder.append("LOWER(email) = ?");
                    parameters.add(email.toLowerCase());
                } else {
                    sqlBuilder.append("LOWER(email) LIKE ?");
                    parameters.add("%" + email.toLowerCase() + "%");
                }
            }

            if (params.containsKey(UserModel.FIRST_NAME)) {
                String firstName = params.get(UserModel.FIRST_NAME);
                sqlBuilder.append(" AND ");
                if (exact) {
                    sqlBuilder.append("LOWER(first_name) = ?");
                    parameters.add(firstName.toLowerCase());
                } else {
                    sqlBuilder.append("LOWER(first_name) LIKE ?");
                    parameters.add("%" + firstName.toLowerCase() + "%");
                }
            }

            if (params.containsKey(UserModel.LAST_NAME)) {
                String lastName = params.get(UserModel.LAST_NAME);
                sqlBuilder.append(" AND ");
                if (exact) {
                    sqlBuilder.append("LOWER(last_name) = ?");
                    parameters.add(lastName.toLowerCase());
                } else {
                    sqlBuilder.append("LOWER(last_name) LIKE ?");
                    parameters.add("%" + lastName.toLowerCase() + "%");
                }
            }

            if (params.containsKey(UserModel.EMAIL_VERIFIED)) {
                boolean emailVerified = Boolean.parseBoolean(params.get(UserModel.EMAIL_VERIFIED));
                sqlBuilder.append(" AND email_verified = ?");
                parameters.add(emailVerified);
            }

            if (params.containsKey(UserModel.ENABLED)) {
                boolean enabled = Boolean.parseBoolean(params.get(UserModel.ENABLED));
                sqlBuilder.append(" AND enabled = ?");
                parameters.add(enabled);
            }

            // Handle custom user attributes
            for (Map.Entry<String, String> entry : params.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();

                // Skip known parameters
                if (UserModel.SEARCH.equals(key) ||
                        UserModel.USERNAME.equals(key) ||
                        UserModel.EMAIL.equals(key) ||
                        UserModel.FIRST_NAME.equals(key) ||
                        UserModel.LAST_NAME.equals(key) ||
                        UserModel.EXACT.equals(key) ||
                        UserModel.EMAIL_VERIFIED.equals(key) ||
                        UserModel.ENABLED.equals(key)) {
                    continue;
                }

                // Assume the key is a custom attribute
                sqlBuilder.append(" AND id IN (SELECT user_id FROM user_attributes WHERE name = ? AND value ");
                if (exact) {
                    sqlBuilder.append("= ?)");
                    parameters.add(key);
                    parameters.add(value);
                } else {
                    sqlBuilder.append("LIKE ?)");
                    parameters.add(key);
                    parameters.add("%" + value + "%");
                }
            }
        }

        // Add ordering and pagination
        sqlBuilder.append(" ORDER BY username ASC");
        if (maxResults != null && maxResults > 0) {
            sqlBuilder.append(" LIMIT ?");
            parameters.add(maxResults);
        }
        if (firstResult != null && firstResult > 0) {
            sqlBuilder.append(" OFFSET ?");
            parameters.add(firstResult);
        }

        String sql = sqlBuilder.toString();
        logger.info("sql=" + sql);

        try (Connection connection = getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            // Set parameters
            for (int i = 0; i < parameters.size(); i++) {
                stmt.setObject(i + 1, parameters.get(i));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    users.add(mapUser(rs, realm));
                }
            }
        } catch (SQLException e) {
            logger.error("Error searching for users", e);
        }

        return users.stream();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer integer, Integer integer1) {
        logger.info("getGroupMembers");
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String s, String s1) {
        logger.info("searchForUserByUserAttribute");
        return Stream.empty();
    }

    @Override
    public void close() {
    }
}
