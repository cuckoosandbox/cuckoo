--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

-- CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

-- COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

--
-- Name: status_type; Type: TYPE; Schema: public; Owner: cuckoo
--

CREATE TYPE status_type AS ENUM (
    'pending',
    'running',
    'completed',
    'reported',
    'recovered'
);


ALTER TYPE public.status_type OWNER TO cuckoo;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO cuckoo;

--
-- Name: errors; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE errors (
    id integer NOT NULL,
    message character varying(255) NOT NULL,
    task_id integer NOT NULL
);


ALTER TABLE public.errors OWNER TO cuckoo;

--
-- Name: errors_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE errors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.errors_id_seq OWNER TO cuckoo;

--
-- Name: errors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE errors_id_seq OWNED BY errors.id;


--
-- Name: guests; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE guests (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    label character varying(255) NOT NULL,
    manager character varying(255) NOT NULL,
    started_on timestamp without time zone NOT NULL,
    shutdown_on timestamp without time zone,
    task_id integer NOT NULL
);


ALTER TABLE public.guests OWNER TO cuckoo;

--
-- Name: guests_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE guests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.guests_id_seq OWNER TO cuckoo;

--
-- Name: guests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE guests_id_seq OWNED BY guests.id;


--
-- Name: machines; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE machines (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    label character varying(255) NOT NULL,
    ip character varying(255) NOT NULL,
    platform character varying(255) NOT NULL,
    interface character varying(255),
    snapshot character varying(255),
    locked boolean NOT NULL,
    locked_changed_on timestamp without time zone,
    status character varying(255),
    status_changed_on timestamp without time zone,
    resultserver_ip character varying(255) NOT NULL,
    resultserver_port character varying(255) NOT NULL
);


ALTER TABLE public.machines OWNER TO cuckoo;

--
-- Name: machines_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE machines_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.machines_id_seq OWNER TO cuckoo;

--
-- Name: machines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE machines_id_seq OWNED BY machines.id;


--
-- Name: machines_tags; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE machines_tags (
    machine_id integer,
    tag_id integer
);


ALTER TABLE public.machines_tags OWNER TO cuckoo;

--
-- Name: samples; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE samples (
    id integer NOT NULL,
    file_size integer NOT NULL,
    file_type character varying(255) NOT NULL,
    md5 character varying(32) NOT NULL,
    crc32 character varying(8) NOT NULL,
    sha1 character varying(40) NOT NULL,
    sha256 character varying(64) NOT NULL,
    sha512 character varying(128) NOT NULL,
    ssdeep character varying(255)
);


ALTER TABLE public.samples OWNER TO cuckoo;

--
-- Name: samples_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE samples_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.samples_id_seq OWNER TO cuckoo;

--
-- Name: samples_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE samples_id_seq OWNED BY samples.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE tags (
    id integer NOT NULL,
    name character varying(255) NOT NULL
);


ALTER TABLE public.tags OWNER TO cuckoo;

--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tags_id_seq OWNER TO cuckoo;

--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE tags_id_seq OWNED BY tags.id;


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE tasks (
    id integer NOT NULL,
    target text NOT NULL,
    category character varying(255) NOT NULL,
    timeout integer DEFAULT 0 NOT NULL,
    priority integer DEFAULT 1 NOT NULL,
    custom character varying(255),
    machine character varying(255),
    package character varying(255),
    options character varying(255),
    platform character varying(255),
    memory boolean NOT NULL,
    enforce_timeout boolean NOT NULL,
    clock timestamp without time zone NOT NULL,
    added_on timestamp without time zone NOT NULL,
    started_on timestamp without time zone,
    completed_on timestamp without time zone,
    status status_type DEFAULT 'pending'::status_type NOT NULL,
    sample_id integer
);


ALTER TABLE public.tasks OWNER TO cuckoo;

--
-- Name: tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: cuckoo
--

CREATE SEQUENCE tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tasks_id_seq OWNER TO cuckoo;

--
-- Name: tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: cuckoo
--

ALTER SEQUENCE tasks_id_seq OWNED BY tasks.id;


--
-- Name: tasks_tags; Type: TABLE; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE TABLE tasks_tags (
    task_id integer,
    tag_id integer
);


ALTER TABLE public.tasks_tags OWNER TO cuckoo;

--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY errors ALTER COLUMN id SET DEFAULT nextval('errors_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY guests ALTER COLUMN id SET DEFAULT nextval('guests_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY machines ALTER COLUMN id SET DEFAULT nextval('machines_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY samples ALTER COLUMN id SET DEFAULT nextval('samples_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tags ALTER COLUMN id SET DEFAULT nextval('tags_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tasks ALTER COLUMN id SET DEFAULT nextval('tasks_id_seq'::regclass);


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO alembic_version VALUES ('263a45963c72');

--
-- Data for Name: errors; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

--
-- Name: errors_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('errors_id_seq', 1, false);


--
-- Data for Name: guests; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO guests VALUES (1, 'cuckoo1', 'cuckoo1', 'VirtualBox', '2017-02-07 12:31:14.986744', '2017-02-07 12:31:32.547285', 1);


--
-- Name: guests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('guests_id_seq', 1, true);


--
-- Data for Name: machines; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO machines VALUES (1, 'cuckoo1', 'cuckoo1', '192.168.56.101', 'windows', null, null, false,	'2017-02-07 12:31:32.573531', 'poweroff', '2017-02-07 12:31:32.530624', '192.168.56.1', 2042);

--
-- Name: machines_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('machines_id_seq', 1, true);


--
-- Data for Name: machines_tags; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

--
-- Data for Name: samples; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO samples VALUES (1, 2048, 'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows', 'e1590ab0ba8fa41b4b8396a7b8370154', 'C56B25A6', '3f3617b860e16f02fc3434c511d37efc3b2db75a', '212153e5e27996d1dd7d9e01921781cf6d9426aba552017ec5e30714b61e9981', '3ccc2ff27b10a0b6722e98595f47fb41ff1bf5af91ade424834b00e1dae7114de8a314ebdbdc9683a2347949fb1140b8f41382800af205d47e8ce1a7803d971d', null);

--
-- Name: samples_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('samples_id_seq', 2, true);


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

--
-- Name: tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('tags_id_seq', 1, false);


--
-- Data for Name: tasks; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO tasks VALUES (1, '/tmp/msgbox.exe', 'file', 0, 1, 'custom1', null, null, 'human=1', null, false, false, '2017-02-07 12:31:08.162074', '2017-02-07 12:31:08.162088', '2017-02-07 12:31:14.90359', '2017-02-07 12:31:32.602948', 'reported', 1);
INSERT INTO tasks VALUES (2, '/tmp/msgbox.exe', 'file', 0, 1, null, null, null, null, null, false, false, '2017-02-07 12:31:51.831581', '2017-02-07 12:31:51.831595', null, null, 'pending', 1);

--
-- Name: tasks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('tasks_id_seq', 2, true);


--
-- Data for Name: tasks_tags; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

--
-- Name: alembic_version_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY alembic_version
    ADD CONSTRAINT alembic_version_pkey PRIMARY KEY (version_num);


--
-- Name: errors_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY errors
    ADD CONSTRAINT errors_pkey PRIMARY KEY (id);


--
-- Name: guests_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY guests
    ADD CONSTRAINT guests_pkey PRIMARY KEY (id);


--
-- Name: guests_task_id_key; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY guests
    ADD CONSTRAINT guests_task_id_key UNIQUE (task_id);


--
-- Name: machines_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY machines
    ADD CONSTRAINT machines_pkey PRIMARY KEY (id);


--
-- Name: samples_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY samples
    ADD CONSTRAINT samples_pkey PRIMARY KEY (id);


--
-- Name: tags_name_key; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY tags
    ADD CONSTRAINT tags_name_key UNIQUE (name);


--
-- Name: tags_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (id);


--
-- Name: hash_index; Type: INDEX; Schema: public; Owner: cuckoo; Tablespace:
--

CREATE UNIQUE INDEX hash_index ON samples USING btree (md5, crc32, sha1, sha256, sha512);


--
-- Name: errors_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY errors
    ADD CONSTRAINT errors_task_id_fkey FOREIGN KEY (task_id) REFERENCES tasks(id);


--
-- Name: guests_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY guests
    ADD CONSTRAINT guests_task_id_fkey FOREIGN KEY (task_id) REFERENCES tasks(id);


--
-- Name: machines_tags_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY machines_tags
    ADD CONSTRAINT machines_tags_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES machines(id);


--
-- Name: machines_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY machines_tags
    ADD CONSTRAINT machines_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES tags(id);


--
-- Name: tasks_sample_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tasks
    ADD CONSTRAINT tasks_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES samples(id);


--
-- Name: tasks_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tasks_tags
    ADD CONSTRAINT tasks_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES tags(id);


--
-- Name: tasks_tags_task_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tasks_tags
    ADD CONSTRAINT tasks_tags_task_id_fkey FOREIGN KEY (task_id) REFERENCES tasks(id);


--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

