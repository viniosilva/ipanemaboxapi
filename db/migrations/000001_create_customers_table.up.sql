CREATE TABLE customers (
    id bigint NOT NULL AUTO_INCREMENT,
    created_at datetime NOT NULL,
    updated_at datetime NOT NULL,
    deleted_at datetime,

    fullname varchar(128) NOT NULL,
    email varchar(128) NOT NULL,

    PRIMARY KEY (ID)
);
