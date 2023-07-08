-- +goose Up
    CREATE TABLE persons (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        age INT NOT NULL,
        family VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL
    );

    INSERT INTO persons (name, age, family, username, password, role)
    VALUES ('Admin', 30, 'admin', 'admin', 'admin', 'admin');
-- +goose Down
    DROP TABLE persons;

