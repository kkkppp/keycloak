create database platform;

create user keycloak with password 'qwerty';

create user platform with password 'qwerty';

\connect platform

GRANT ALL ON SCHEMA public TO keycloak;

GRANT ALL ON SCHEMA public TO platform;

-- Enable the uuid-ossp extension for UUID generation (PostgreSQL specific)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the users table with UUID primary key
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT TRUE
);

-- Create an index on username for faster lookups
CREATE INDEX idx_users_username ON users(username);

-- Create an index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- Create the user_attributes table with UUID primary key and foreign key
CREATE TABLE user_attributes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    value VARCHAR(255),
    UNIQUE (user_id, name)
);

-- Create an index on user_id for faster lookups
CREATE INDEX idx_user_attributes_user_id ON user_attributes(user_id);

-- Optional: Create indexes on name and value if you frequently search by attributes
CREATE INDEX idx_user_attributes_name ON user_attributes(name);
CREATE INDEX idx_user_attributes_value ON user_attributes(value);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO keycloak;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE user_attributes TO keycloak;

insert into users(username, email, first_name, last_name, password_hash) values ('admin', 'kirill.paliy@gmail.com','Kir','P','$2a$10$F.RKkkj5BaSipxxpAQnx2.dogjoEsBNvgSLAwvcgkvQcUYThxke52');
insert into users(username, email, first_name, last_name, password_hash) values ('system','system@example.com','Service','Account','$2a$10$GScPuSmLxLwwdOCmar1abOCXr9xSogz/1/ABBKRXy8YMAnS6cUqr2');
