-- has to change user name to real one(someone -> yours)

CREATE SEQUENCE jwt_user_id_seq;
CREATE SEQUENCE jwt_role_id_seq;
CREATE SEQUENCE jwt_rest_id_seq;

-- jwt user
CREATE TABLE public.jwt_user (
	id numeric NOT NULL DEFAULT nextval('jwt_user_id_seq'::regclass),
	username varchar(30) NOT NULL,
	"password" varchar(300) NOT NULL,
	enabled bpchar(1) NOT NULL DEFAULT 't'::bpchar,
	reg_datetime timestamp NOT NULL DEFAULT now(),
	reg_id varchar(30) NOT NULL,
	upt_datetime timestamp NOT NULL DEFAULT now(),
	upt_id varchar(30) NOT NULL,
	CONSTRAINT jwt_user_pk PRIMARY KEY (id)
);

ALTER TABLE public.jwt_user OWNER TO someone;
GRANT ALL ON TABLE public.jwt_user TO someone;

-- jwt rest
CREATE TABLE public.jwt_rest (
	id numeric NOT NULL DEFAULT nextval('jwt_rest_id_seq'::regclass),
	rest_url varchar(30) NOT NULL,
	enabled bpchar(1) NOT NULL DEFAULT 't'::bpchar,
	reg_datetime timestamp NOT NULL DEFAULT now(),
	reg_id varchar(30) NOT NULL,
	upt_datetime timestamp NOT NULL DEFAULT now(),
	upt_id varchar(30) NOT NULL,
	CONSTRAINT jwt_rest_pk PRIMARY KEY (id)
);

ALTER TABLE public.jwt_rest OWNER TO someone;
GRANT ALL ON TABLE public.jwt_rest TO someone;

-- jwt role
CREATE TABLE public.jwt_role (
	id numeric NOT NULL DEFAULT nextval('jwt_role_id_seq'::regclass),
	rolename varchar(30) NOT NULL,
	enabled bpchar(1) NOT NULL DEFAULT 't'::bpchar,
	reg_datetime timestamp NOT NULL DEFAULT now(),
	reg_id varchar(30) NOT NULL,
	upt_datetime timestamp NOT NULL DEFAULT now(),
	upt_id varchar(30) NOT NULL,
	CONSTRAINT jwt_role_pk PRIMARY KEY (id)
);

ALTER TABLE public.jwt_role OWNER TO someone;
GRANT ALL ON TABLE public.jwt_role TO someone;

-- jwt policy
CREATE TABLE public.jwt_policy (
	role_id numeric NOT NULL,
	rest_id numeric NOT NULL,
	method_name varchar(10) NOT NULL,
	enabled bpchar(1) NOT NULL DEFAULT 't'::bpchar,
	reg_datetime timestamp NOT NULL DEFAULT now(),
	reg_id varchar(30) NOT NULL,
	upt_datetime timestamp NOT NULL DEFAULT now(),
	upt_id varchar(30) NOT NULL,
	CONSTRAINT jwt_policy_pk PRIMARY KEY (role_id, rest_id),
	CONSTRAINT jwt_policy_jwt_rest_fk FOREIGN KEY (rest_id) REFERENCES jwt_rest(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
	CONSTRAINT jwt_policy_jwt_role_fk FOREIGN KEY (role_id) REFERENCES jwt_role(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

ALTER TABLE public.jwt_policy OWNER TO someone;
GRANT ALL ON TABLE public.jwt_policy TO someone;

-- jwt permission
CREATE TABLE public.jwt_permission (
	user_id numeric NOT NULL,
	role_id numeric NOT NULL,
	enabled bpchar(1) NOT NULL DEFAULT 't'::bpchar,
	reg_datetime timestamp NOT NULL DEFAULT now(),
	reg_id varchar(30) NOT NULL,
	upt_datetime timestamp NOT NULL DEFAULT now(),
	upt_id varchar(30) NOT NULL,
	CONSTRAINT jwt_permission_pk PRIMARY KEY (user_id, role_id),
	CONSTRAINT jwt_permission_jwt_rest_fk FOREIGN KEY (user_id) REFERENCES jwt_user(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
	CONSTRAINT jwt_permission_jwt_role_fk FOREIGN KEY (role_id) REFERENCES jwt_role(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

ALTER TABLE public.jwt_permission OWNER TO someone;
GRANT ALL ON TABLE public.jwt_permission TO someone;
