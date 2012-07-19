--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: postgres; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON DATABASE postgres IS 'default administrative connection database';


--
-- Name: dynvpn; Type: SCHEMA; Schema: -; Owner: nib
--

CREATE SCHEMA dynvpn;


ALTER SCHEMA dynvpn OWNER TO nib;

--
-- Name: SCHEMA dynvpn; Type: COMMENT; Schema: -; Owner: nib
--

COMMENT ON SCHEMA dynvpn IS 'Dynamic VPN';


--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA dynvpn;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET search_path = dynvpn, pg_catalog;

--
-- Name: inet_mask(inet, inet); Type: FUNCTION; Schema: dynvpn; Owner: nib
--

CREATE FUNCTION inet_mask(inet, inet) RETURNS inet
    LANGUAGE sql IMMUTABLE
    AS $_$ select set_masklen($1,i) from generate_series(0, case when family($2)=4 then 32 else 128 end) i where netmask(set_masklen($1::cidr, i)) = $2; $_$;


ALTER FUNCTION dynvpn.inet_mask(inet, inet) OWNER TO nib;

--
-- Name: client_id_seq; Type: SEQUENCE; Schema: dynvpn; Owner: nib
--

CREATE SEQUENCE client_id_seq
    START WITH 1000
    INCREMENT BY 1
    MINVALUE 0
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dynvpn.client_id_seq OWNER TO nib;

--
-- Name: client_id_seq; Type: SEQUENCE SET; Schema: dynvpn; Owner: nib
--

SELECT pg_catalog.setval('client_id_seq', 1224, true);


SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: client; Type: TABLE; Schema: dynvpn; Owner: nib; Tablespace: 
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


ALTER TABLE dynvpn.client OWNER TO nib;

--
-- Name: context_id_seq; Type: SEQUENCE; Schema: dynvpn; Owner: nib
--

CREATE SEQUENCE context_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dynvpn.context_id_seq OWNER TO nib;

--
-- Name: context_id_seq; Type: SEQUENCE SET; Schema: dynvpn; Owner: nib
--

SELECT pg_catalog.setval('context_id_seq', 113, true);


--
-- Name: context; Type: TABLE; Schema: dynvpn; Owner: nib; Tablespace: 
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


ALTER TABLE dynvpn.context OWNER TO nib;

--
-- Name: node; Type: TABLE; Schema: dynvpn; Owner: nib; Tablespace: 
--

CREATE TABLE node (
    context_id integer NOT NULL,
    uuid text NOT NULL,
    certificate text NOT NULL,
    privatekey text NOT NULL,
    status integer DEFAULT 0,
    provcode text
);


ALTER TABLE dynvpn.node OWNER TO nib;

--
-- Name: topology_id_seq; Type: SEQUENCE; Schema: dynvpn; Owner: nib
--

CREATE SEQUENCE topology_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dynvpn.topology_id_seq OWNER TO nib;

--
-- Name: topology_id_seq; Type: SEQUENCE SET; Schema: dynvpn; Owner: nib
--

SELECT pg_catalog.setval('topology_id_seq', 3, true);


--
-- Name: topology; Type: TABLE; Schema: dynvpn; Owner: nib; Tablespace: 
--

CREATE TABLE topology (
    id integer DEFAULT nextval('topology_id_seq'::regclass) NOT NULL,
    name text NOT NULL
);


ALTER TABLE dynvpn.topology OWNER TO nib;

--
-- Data for Name: client; Type: TABLE DATA; Schema: dynvpn; Owner: nib
--

COPY client (id, firstname, lastname, email, company, phone, country, state_province, city, postal_code, status, password) FROM stdin;
\.


--
-- Data for Name: context; Type: TABLE DATA; Schema: dynvpn; Owner: nib
--

COPY context (id, topology_id, description, client_id, network, embassy_certificate, embassy_privatekey, embassy_serial, passport_certificate, passport_privatekey) FROM stdin;
\.


--
-- Data for Name: node; Type: TABLE DATA; Schema: dynvpn; Owner: nib
--

COPY node (context_id, uuid, certificate, privatekey, status, provcode) FROM stdin;
\.


--
-- Data for Name: topology; Type: TABLE DATA; Schema: dynvpn; Owner: nib
--

COPY topology (id, name) FROM stdin;
1	mesh
2	hub-and-spoke
3	gateway
\.


--
-- Name: client_id_key; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_id_key UNIQUE (id);


--
-- Name: client_pkey; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_pkey PRIMARY KEY (email);


--
-- Name: context_id_key; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_id_key UNIQUE (id);


--
-- Name: context_pkey; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_pkey PRIMARY KEY (description, client_id);


--
-- Name: passport_client_pkey; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY node
    ADD CONSTRAINT passport_client_pkey PRIMARY KEY (uuid);


--
-- Name: topology_id_key; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY topology
    ADD CONSTRAINT topology_id_key UNIQUE (id);


--
-- Name: topology_pkey; Type: CONSTRAINT; Schema: dynvpn; Owner: nib; Tablespace: 
--

ALTER TABLE ONLY topology
    ADD CONSTRAINT topology_pkey PRIMARY KEY (name);


--
-- Name: context; Type: FK CONSTRAINT; Schema: dynvpn; Owner: nib
--

ALTER TABLE ONLY node
    ADD CONSTRAINT context FOREIGN KEY (context_id) REFERENCES context(id);


--
-- Name: context_client_id_fkey; Type: FK CONSTRAINT; Schema: dynvpn; Owner: nib
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_client_id_fkey FOREIGN KEY (client_id) REFERENCES client(id);


--
-- Name: context_topology_id_fkey; Type: FK CONSTRAINT; Schema: dynvpn; Owner: nib
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_topology_id_fkey FOREIGN KEY (topology_id) REFERENCES topology(id);


--
-- Name: dynvpn; Type: ACL; Schema: -; Owner: nib
--

REVOKE ALL ON SCHEMA dynvpn FROM PUBLIC;
REVOKE ALL ON SCHEMA dynvpn FROM nib;
GRANT ALL ON SCHEMA dynvpn TO nib;
GRANT ALL ON SCHEMA dynvpn TO PUBLIC;


--
-- PostgreSQL database dump complete
--

