--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

--
-- Name: netvirt; Type: SCHEMA; Schema: -; Owner: netvirt
--

CREATE SCHEMA netvirt;


ALTER SCHEMA netvirt OWNER TO netvirt;

--
-- Name: SCHEMA netvirt; Type: COMMENT; Schema: -; Owner: netvirt
--

COMMENT ON SCHEMA netvirt IS 'www.netvirt.org';


SET search_path = netvirt, pg_catalog;

--
-- Name: inet_mask(inet, inet); Type: FUNCTION; Schema: netvirt; Owner: netvirt
--

CREATE FUNCTION inet_mask(inet, inet) RETURNS inet
    LANGUAGE sql IMMUTABLE
    AS $_$ select set_masklen($1,i) from generate_series(0, case when family($2)=4 then 32 else 128 end) i where netmask(set_masklen($1::cidr, i)) = $2; $_$;


ALTER FUNCTION netvirt.inet_mask(inet, inet) OWNER TO netvirt;

--
-- Name: client_id_seq; Type: SEQUENCE; Schema: netvirt; Owner: netvirt
--

CREATE SEQUENCE client_id_seq
    START WITH 1000
    INCREMENT BY 1
    MINVALUE 0
    NO MAXVALUE
    CACHE 1;


ALTER TABLE netvirt.client_id_seq OWNER TO netvirt;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: client; Type: TABLE; Schema: netvirt; Owner: netvirt; Tablespace:
--

CREATE TABLE client (
    id integer DEFAULT nextval('client_id_seq'::regclass) NOT NULL,
    email text NOT NULL,
    status integer DEFAULT 0 NOT NULL,
    password text NOT NULL,
    "timestamp" date DEFAULT now()
);


ALTER TABLE netvirt.client OWNER TO netvirt;

--
-- Name: context_id_seq; Type: SEQUENCE; Schema: netvirt; Owner: netvirt
--

CREATE SEQUENCE context_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE netvirt.context_id_seq OWNER TO netvirt;

--
-- Name: context; Type: TABLE; Schema: netvirt; Owner: netvirt; Tablespace:
--

CREATE TABLE context (
    id integer DEFAULT nextval('context_id_seq'::regclass) NOT NULL,
    description text NOT NULL,
    client_id integer NOT NULL,
    network cidr NOT NULL,
    embassy_certificate text NOT NULL,
    embassy_privatekey text NOT NULL,
    embassy_serial integer NOT NULL,
    passport_certificate text NOT NULL,
    passport_privatekey text NOT NULL,
    ippool bytea NOT NULL,
    "timestamp" date DEFAULT now()
);


ALTER TABLE netvirt.context OWNER TO netvirt;

--
-- Name: node; Type: TABLE; Schema: netvirt; Owner: netvirt; Tablespace:
--

CREATE TABLE node (
    context_id integer NOT NULL,
    uuid text NOT NULL,
    certificate text NOT NULL,
    privatekey text NOT NULL,
    status integer DEFAULT 0,
    provcode text,
    description text,
    ipaddress text NOT NULL,
    ipsrc text,
    "timestamp" date DEFAULT now()
);


ALTER TABLE netvirt.node OWNER TO netvirt;

--
-- Name: topology_id_seq; Type: SEQUENCE; Schema: netvirt; Owner: netvirt
--

CREATE SEQUENCE topology_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE netvirt.topology_id_seq OWNER TO netvirt;

--
-- Name: client_id_key; Type: CONSTRAINT; Schema: netvirt; Owner: netvirt; Tablespace:
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_id_key UNIQUE (id);


--
-- Name: client_pkey; Type: CONSTRAINT; Schema: netvirt; Owner: netvirt; Tablespace:
--

ALTER TABLE ONLY client
    ADD CONSTRAINT client_pkey PRIMARY KEY (email);


--
-- Name: context_id_key; Type: CONSTRAINT; Schema: netvirt; Owner: netvirt; Tablespace:
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_id_key UNIQUE (id);


--
-- Name: context_pkey; Type: CONSTRAINT; Schema: netvirt; Owner: netvirt; Tablespace:
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_pkey PRIMARY KEY (description, client_id);


--
-- Name: passport_client_pkey; Type: CONSTRAINT; Schema: netvirt; Owner: netvirt; Tablespace:
--

ALTER TABLE ONLY node
    ADD CONSTRAINT passport_client_pkey PRIMARY KEY (uuid);


--
-- Name: context; Type: FK CONSTRAINT; Schema: netvirt; Owner: netvirt
--

ALTER TABLE ONLY node
    ADD CONSTRAINT context FOREIGN KEY (context_id) REFERENCES context(id);


--
-- Name: context_client_id_fkey; Type: FK CONSTRAINT; Schema: netvirt; Owner: netvirt
--

ALTER TABLE ONLY context
    ADD CONSTRAINT context_client_id_fkey FOREIGN KEY (client_id) REFERENCES client(id);


--
-- Name: netvirt; Type: ACL; Schema: -; Owner: netvirt
--

REVOKE ALL ON SCHEMA netvirt FROM PUBLIC;
REVOKE ALL ON SCHEMA netvirt FROM netvirt;
GRANT ALL ON SCHEMA netvirt TO netvirt;
GRANT ALL ON SCHEMA netvirt TO PUBLIC;


--
-- PostgreSQL database dump complete
--

