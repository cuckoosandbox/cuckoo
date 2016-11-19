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
    'processing',
    'failure',
    'success'
);


ALTER TYPE public.status_type OWNER TO cuckoo;

SET default_tablespace = '';

SET default_with_oids = false;

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
    locked boolean NOT NULL,
    locked_changed_on timestamp without time zone,
    status character varying(255),
    status_changed_on timestamp without time zone
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

ALTER TABLE ONLY tasks ALTER COLUMN id SET DEFAULT nextval('tasks_id_seq'::regclass);


--
-- Data for Name: errors; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO errors VALUES (1, 'Trying to start an already started vm cuckoo7', 1);


--
-- Name: errors_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('errors_id_seq', 1, true);


--
-- Data for Name: guests; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO guests VALUES (1, 'cuckoo1', 'cuckoo7', 'VirtualBox', '2016-11-15 19:21:53.943225', '2016-11-15 19:21:55.287257', 1);
INSERT INTO guests VALUES (2, 'cuckoo1', 'cuckoo7', 'VirtualBox', '2016-11-15 19:22:06.627794', '2016-11-15 19:24:19.940193', 2);
INSERT INTO guests VALUES (3, 'cuckoo1', 'cuckoo7', 'VirtualBox', '2016-11-15 19:24:20.493594', NULL, 3);


--
-- Name: guests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('guests_id_seq', 3, true);


--
-- Data for Name: machines; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO machines VALUES (3, 'cuckoo1', 'cuckoo7', '192.168.56.101', 'windows', true, '2016-11-15 19:24:20.453466', 'poweroff', '2016-11-15 19:24:30.862315');
INSERT INTO machines VALUES (4, 'cuckoo2', 'cuckoo8', '192.168.56.102', 'windows', true, null, 'poweroff', null);


--
-- Name: machines_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('machines_id_seq', 3, true);


--
-- Data for Name: samples; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO samples VALUES (1, 2048, 'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows', 'e1590ab0ba8fa41b4b8396a7b8370154', 'C56B25A6', '3f3617b860e16f02fc3434c511d37efc3b2db75a', '212153e5e27996d1dd7d9e01921781cf6d9426aba552017ec5e30714b61e9981', '3ccc2ff27b10a0b6722e98595f47fb41ff1bf5af91ade424834b00e1dae7114de8a314ebdbdc9683a2347949fb1140b8f41382800af205d47e8ce1a7803d971d', NULL);


--
-- Name: samples_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('samples_id_seq', 3, true);


--
-- Data for Name: tasks; Type: TABLE DATA; Schema: public; Owner: cuckoo
--

INSERT INTO tasks VALUES (1, '/tmp/msgbox.exe', 'file', 0, 1, '', '', '', '', '', false, false, '2016-11-15 19:21:50.836483', '2016-11-15 19:21:53.86149', '2016-11-15 19:21:55.34773', 'failure', 1);
INSERT INTO tasks VALUES (2, '/tmp/msgbox.exe', 'file', 0, 1, '', '', '', '', '', false, false, '2016-11-15 19:22:03.046324', '2016-11-15 19:22:06.541378', '2016-11-15 19:24:20.701015', 'success', 1);
INSERT INTO tasks VALUES (3, '/tmp/msgbox.exe', 'file', 0, 1, '', '', '', '', '', false, false, '2016-11-15 19:22:03.699344', '2016-11-15 19:24:20.406222', NULL, 'processing', 1);


--
-- Name: tasks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: cuckoo
--

SELECT pg_catalog.setval('tasks_id_seq', 3, true);


--
-- Name: errors_pkey; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY errors
    ADD CONSTRAINT errors_pkey PRIMARY KEY (id);


--
-- Name: errors_task_id_key; Type: CONSTRAINT; Schema: public; Owner: cuckoo; Tablespace:
--

ALTER TABLE ONLY errors
    ADD CONSTRAINT errors_task_id_key UNIQUE (task_id);


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
-- Name: tasks_sample_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: cuckoo
--

ALTER TABLE ONLY tasks
    ADD CONSTRAINT tasks_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES samples(id);


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

