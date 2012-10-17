--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: dnds; Type: SCHEMA; Schema: -; Owner: dnds
--

CREATE SCHEMA dnds;


ALTER SCHEMA dnds OWNER TO dnds;

--
-- Name: SCHEMA dnds; Type: COMMENT; Schema: -; Owner: dnds
--

COMMENT ON SCHEMA dnds IS 'Dynamic Network Directory Service';


SET search_path = dnds, pg_catalog;

--
-- Name: inet_mask(inet, inet); Type: FUNCTION; Schema: dnds; Owner: dnds
--

CREATE FUNCTION inet_mask(inet, inet) RETURNS inet
    LANGUAGE sql IMMUTABLE
    AS $_$ select set_masklen($1,i) from generate_series(0, case when family($2)=4 then 32 else 128 end) i where netmask(set_masklen($1::cidr, i)) = $2; $_$;


ALTER FUNCTION dnds.inet_mask(inet, inet) OWNER TO dnds;

--
-- Name: client_id_seq; Type: SEQUENCE; Schema: dnds; Owner: dnds
--

CREATE SEQUENCE client_id_seq
    START WITH 1000
    INCREMENT BY 1
    NO MAXVALUE
    MINVALUE 0
    CACHE 1;


ALTER TABLE dnds.client_id_seq OWNER TO dnds;

--
-- Name: client_id_seq; Type: SEQUENCE SET; Schema: dnds; Owner: dnds
--

SELECT pg_catalog.setval('client_id_seq', 1000, false);


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: client; Type: TABLE; Schema: dnds; Owner: dnds; Tablespace: 
--

CREATE TABLE client (
    id integer DEFAULT nextval('client_id_seq'::regclass) NOT NULL,
    firstname text NOT NULL,
    lastname text NOT NULL,
    email text NOT NULL,
    company text,
    phone text NOT NULL,
    country text NOT NULL,
    state_province text NOT NULL,
    city text NOT NULL,
    postal_code text NOT NULL,
    status integer DEFAULT 0 NOT NULL,
    password text NOT NULL
);


ALTER TABLE dnds.client OWNER TO dnds;

--
-- Name: context_id_seq; Type: SEQUENCE; Schema: dnds; Owner: dnds
--

CREATE SEQUENCE context_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE dnds.context_id_seq OWNER TO dnds;

--
-- Name: context_id_seq; Type: SEQUENCE SET; Schema: dnds; Owner: dnds
--

SELECT pg_catalog.setval('context_id_seq', 1, false);


--
-- Name: context; Type: TABLE; Schema: dnds; Owner: dnds; Tablespace: 
--

CREATE TABLE context (
    id integer DEFAULT nextval('context_id_seq'::regclass) NOT NULL,
    topology_id integer NOT NULL,
    description text NOT NULL,
    client_id integer NOT NULL,
    network cidr NOT NULL,
    embassy_certificate text NOT NULL,
    embassy_privatekey text NOT NULL,
    embassy_serial integer NOT NULL,
    passport_certificate text NOT NULL,
    passport_privatekey text NOT NULL
);


ALTER TABLE dnds.context OWNER TO dnds;

--
-- Name: node; Type: TABLE; Schema: dnds; Owner: dnds; Tablespace: 
--

CREATE TABLE node (
    context_id integer NOT NULL,
    uuid text NOT NULL,
    certificate text NOT NULL,
    privatekey text NOT NULL,
    status integer DEFAULT 0,
    provcode text,
    description text
);


ALTER TABLE dnds.node OWNER TO dnds;

--
-- Name: topology_id_seq; Type: SEQUENCE; Schema: dnds; Owner: dnds
--

CREATE SEQUENCE topology_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;


ALTER TABLE dnds.topology_id_seq OWNER TO dnds;

--
-- Name: topology_id_seq; Type: SEQUENCE SET; Schema: dnds; Owner: dnds
--

SELECT pg_catalog.setval('topology_id_seq', 3, true);


--
-- Name: topology; Type: TABLE; Schema: dnds; Owner: dnds; Tablespace: 
--

CREATE TABLE topology (
    id integer DEFAULT nextval('topology_id_seq'::regclass) NOT NULL,
    name text NOT NULL
);


ALTER TABLE dnds.topology OWNER TO dnds;

--
-- Data for Name: client; Type: TABLE DATA; Schema: dnds; Owner: dnds
--

COPY client (id, firstname, lastname, email, company, phone, country, state_province, city, postal_code, status, password) FROM stdin;
\.


--
-- Data for Name: context; Type: TABLE DATA; Schema: dnds; Owner: dnds
--

COPY context (id, topology_id, description, client_id, network, embassy_certificate, embassy_privatekey, embassy_serial, passport_certificate, passport_privatekey) FROM stdin;
\.


--
-- Data for Name: node; Type: TABLE DATA; Schema: dnds; Owner: dnds
--

COPY node (context_id, uuid, certificate, privatekey, status, provcode, description) FROM stdin;
\.


--
-- Data for Name: topology; Type: TABLE DATA; Schema: dnds; Owner: dnds
--

COPY topology (id, name) FROM stdin;
1	mesh
2	hub-and-spoke
3	gateway
\.


--
-- Name: client_id_key; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_id_key UNIQUE (id);


--
-- Name: client_pkey; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_pkey PRIMARY KEY (email);


--
-- Name: context_id_key; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_id_key UNIQUE (id);


--
-- Name: context_pkey; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_pkey PRIMARY KEY (description, client_id);


--
-- Name: passport_client_pkey; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY node
    ADD CONSTRAINT passport_client_pkey PRIMARY KEY (uuid);


--
-- Name: topology_id_key; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY topology
    ADD CONSTRAINT topology_id_key UNIQUE (id);


--
-- Name: topology_pkey; Type: CONSTRAINT; Schema: dnds; Owner: dnds; Tablespace: 
--

ALTER TABLE ONLY topology
    ADD CONSTRAINT topology_pkey PRIMARY KEY (name);


--
-- Name: context; Type: FK CONSTRAINT; Schema: dnds; Owner: dnds
--

ALTER TABLE ONLY node
    ADD CONSTRAINT context FOREIGN KEY (context_id) REFERENCES context(id);


--
-- Name: context_client_id_fkey; Type: FK CONSTRAINT; Schema: dnds; Owner: dnds
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_client_id_fkey FOREIGN KEY (client_id) REFERENCES client(id);


--
-- Name: context_topology_id_fkey; Type: FK CONSTRAINT; Schema: dnds; Owner: dnds
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_topology_id_fkey FOREIGN KEY (topology_id) REFERENCES topology(id);


--
-- Name: dnds; Type: ACL; Schema: -; Owner: dnds
--

REVOKE ALL ON SCHEMA dnds FROM PUBLIC;
REVOKE ALL ON SCHEMA dnds FROM dnds;
GRANT ALL ON SCHEMA dnds TO dnds;
GRANT ALL ON SCHEMA dnds TO PUBLIC;


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

