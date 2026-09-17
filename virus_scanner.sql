CREATE DATABASE virus_scanner;

USE virus_scanner;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255),
    timestamp DATETIME,
    filename VARCHAR(255),
    file_hash VARCHAR(255),
    result TEXT
);
select*from users;
select*from scans;