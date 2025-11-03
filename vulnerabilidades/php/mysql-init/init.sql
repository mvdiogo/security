-- Garantir que o banco é criado e usado
CREATE DATABASE IF NOT EXISTS appdb;
USE appdb;

-- Tabela customers
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20)
);

-- Inserir dados de exemplo
INSERT INTO customers (name, email, phone) VALUES 
('Alice', 'alice@example.com', '123-456-7890'),
('Bob', 'bob@example.com', '123-456-7891'),
('Charlie', 'charlie@example.com', '123-456-7892'),
('David', 'david@example.com', '123-456-7893');

-- Tabela users
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),
    is_admin BOOLEAN DEFAULT FALSE
);

INSERT INTO users (username, password, is_admin) VALUES 
('admin', 'secret123', TRUE),
('user1', 'pass123', FALSE),
('test', 'test123', FALSE);

-- Verificar se as tabelas foram criadas
SHOW TABLES;