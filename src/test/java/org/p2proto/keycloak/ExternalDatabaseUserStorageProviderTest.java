package org.p2proto.keycloak;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ExternalDatabaseUserStorageProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private ComponentModel model;

    @Mock
    private HikariDataSource dataSource;

    @Mock
    private Connection connection;

    @Mock
    private PreparedStatement preparedStatement;

    @Mock
    private ResultSet resultSet;

    @Mock
    private RealmModel realm;

    private ExternalDatabaseUserStorageProvider provider;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        provider = new ExternalDatabaseUserStorageProvider(session, model, dataSource);
    }

    @Test
    void testGetUserById_validFormatAndMatchesProvider() throws SQLException {
        // The provider ID matches
        when(model.getId()).thenReturn("someComponentId");

        // The code will call getConnection -> prepareStatement -> executeQuery -> next -> getString(...)
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);

        when(resultSet.next()).thenReturn(true).thenReturn(false);
        when(resultSet.getString("id")).thenReturn("abc123");
        when(resultSet.getString("username")).thenReturn("john_doe");
        when(resultSet.getString("email")).thenReturn("john@example.com");
        when(resultSet.getString("first_name")).thenReturn("John");
        when(resultSet.getString("last_name")).thenReturn("Doe");

        String keycloakUserId = "f:someComponentId:abc123";
        UserModel userModel = provider.getUserById(realm, keycloakUserId);

        assertNotNull(userModel);
        assertEquals("john_doe", userModel.getUsername());
        assertEquals("john@example.com", userModel.getEmail());
        assertEquals("John", userModel.getFirstName());
        assertEquals("Doe", userModel.getLastName());
        assertEquals("f:someComponentId:abc123", userModel.getId());

        // Verify the SQL call
        verify(connection).prepareStatement(
                "SELECT id, username, email, first_name, last_name FROM users WHERE id = ?::uuid"
        );
        verify(preparedStatement).setString(1, "abc123");
    }

    @Test
    void testGetUserById_componentMismatch() {
        // ID mismatches => the code should return null without DB calls
        when(model.getId()).thenReturn("correctComponentId");
        String keycloakUserId = "f:wrongComponentId:abc123";

        UserModel userModel = provider.getUserById(realm, keycloakUserId);
        assertNull(userModel, "Expected null when component ID does not match");
    }

    @Test
    void testGetUserById_invalidFormat() {
        // The ID doesn't match the expected "f:<componentId>:<uuid>" format
        when(model.getId()).thenReturn("someComponentId");
        String keycloakUserId = "invalidFormat";

        UserModel userModel = provider.getUserById(realm, keycloakUserId);
        assertNull(userModel, "Expected null when user ID format is invalid");
    }

    @Test
    void testGetUserById_userNotFound() throws SQLException {
        when(model.getId()).thenReturn("someComponentId");
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        // resultSet has no rows => next() = false
        when(resultSet.next()).thenReturn(false);

        String keycloakUserId = "f:someComponentId:abc123";
        UserModel userModel = provider.getUserById(realm, keycloakUserId);

        assertNull(userModel, "Expected null if no user is found in the DB");
    }

    @Test
    void testGetUserByUsername_found() throws SQLException {
        String username = "jane_doe";

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);

        when(resultSet.next()).thenReturn(true).thenReturn(false);
        when(resultSet.getString("id")).thenReturn("123");
        when(resultSet.getString("username")).thenReturn(username);
        when(resultSet.getString("email")).thenReturn("jane@example.com");
        when(resultSet.getString("first_name")).thenReturn("Jane");
        when(resultSet.getString("last_name")).thenReturn("Doe");

        UserModel userModel = provider.getUserByUsername(realm, username);

        assertNotNull(userModel);
        assertEquals(username, userModel.getUsername());
        verify(preparedStatement).setString(1, username);
    }

    @Test
    void testGetUserByUsername_notFound() throws SQLException {
        String username = "non_existent_user";

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        // No rows
        when(resultSet.next()).thenReturn(false);

        UserModel userModel = provider.getUserByUsername(realm, username);
        assertNull(userModel);
    }

    @Test
    void testIsValid_passwordMatches() throws SQLException {
        String testUsername = "user1";
        String testPassword = "secret123";
        String hashedPassword = org.mindrot.jbcrypt.BCrypt.hashpw(
                testPassword, org.mindrot.jbcrypt.BCrypt.gensalt()
        );

        // Mock user + credential
        UserModel userModel = mock(UserModel.class);
        when(userModel.getUsername()).thenReturn(testUsername);

        CredentialInput credentialInput = mock(CredentialInput.class);
        when(credentialInput.getType()).thenReturn("password");
        when(credentialInput.getChallengeResponse()).thenReturn(testPassword);

        // The code checks the DB for password_hash
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);

        // Row found => next() = true => code calls getString("password_hash")
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString("password_hash")).thenReturn(hashedPassword);

        boolean valid = provider.isValid(realm, userModel, credentialInput);
        assertTrue(valid, "Expected credentials to be valid when bcrypt hashes match");
    }

    @Test
    void testIsValid_passwordMismatch() throws SQLException {
        String testUsername = "user1";
        String correctPassword = "secret123";
        String wrongPassword = "wrongSecret";
        String hashedPassword = org.mindrot.jbcrypt.BCrypt.hashpw(
                correctPassword, org.mindrot.jbcrypt.BCrypt.gensalt()
        );

        UserModel userModel = mock(UserModel.class);
        when(userModel.getUsername()).thenReturn(testUsername);

        CredentialInput credentialInput = mock(CredentialInput.class);
        when(credentialInput.getType()).thenReturn("password");
        when(credentialInput.getChallengeResponse()).thenReturn(wrongPassword);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);

        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString("password_hash")).thenReturn(hashedPassword);

        boolean valid = provider.isValid(realm, userModel, credentialInput);
        assertFalse(valid, "Expected invalid credentials when the password doesn't match the hash");
    }

    @Test
    void testIsValid_userNotFound() throws SQLException {
        String testUsername = "unknown";
        String testPassword = "doesntMatter";

        UserModel userModel = mock(UserModel.class);
        when(userModel.getUsername()).thenReturn(testUsername);

        CredentialInput credentialInput = mock(CredentialInput.class);
        when(credentialInput.getType()).thenReturn("password");
        when(credentialInput.getChallengeResponse()).thenReturn(testPassword);

        // No row => next()=false => never calls getString("password_hash")
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(false);

        boolean valid = provider.isValid(realm, userModel, credentialInput);
        assertFalse(valid, "Expected invalid credentials when the user cannot be found in the DB");
    }
}
