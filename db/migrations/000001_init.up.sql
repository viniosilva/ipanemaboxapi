CREATE TABLE users (
    id        uuid PRIMARY KEY,
	name      varchar(255) NOT NULL,
	email     varchar(255) NOT NULL,
	password  varchar(255) NOT NULL,
	phone     varchar(20) NULL,
	created_at timestamp with time zone NOT NULL,
	updated_at timestamp with time zone NOT NULL,
	deleted_at timestamp with time zone NULL
);