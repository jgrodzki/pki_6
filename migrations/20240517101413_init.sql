CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL UNIQUE,
    joined TIMESTAMP NOT NULL DEFAULT NOW(),
    lastvisit TIMESTAMP NOT NULL DEFAULT NOW(),
    counter INTEGER NOT NULL DEFAULT 1
);

INSERT INTO users (name) VALUES ('a@example.com'), ('b@example.com');
