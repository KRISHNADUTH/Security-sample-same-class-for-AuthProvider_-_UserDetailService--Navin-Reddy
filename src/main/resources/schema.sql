CREATE TABLE Customers (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL ,
    password VARCHAR(100) NOT NULL
);

CREATE TABLE Authorities(
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    authority_name VARCHAR(50),
    customer_id BIGINT,
    CONSTRAINT fk_authorities_users FOREIGN KEY (customer_id) REFERENCES Customers (id)
);


INSERT INTO Customers (username, password) VALUES
('ram', '{bcrypt}$2a$12$S8F3p6FIMrDbcQ2FcfM5auzBjEiqKoUmEYxULPoen8A0gfwr07m8u'),
('don', '{bcrypt}$2a$12$Y.kjBkM6uT/7xlXNTVwnsuU3x8.O/gpm8O.ArheE80mNBVTE4n8eS'),
('sam', '{bcrypt}$2a$12$8pe9Xi.7TiAY3RDpj.efZeb8vDtDVunOnDP/iS1zCY4JZbs6iOxDy');


INSERT INTO Authorities ( authority_name, customer_id) VALUES
('ROLE_ADMIN', 1),
('ROLE_USER', 1),
('ROLE_USER', 2),
('ROLE_USER', 3);
