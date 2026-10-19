-- =====================================================================
-- Securing Snowflake: Network Policies, Auth Policies, and Trust Center
-- Hands-on lab. Run each section top to bottom in a Snowsight worksheet.
--
-- All policies are applied at the USER level, so nobody can lock
-- themselves out of their account during the lab.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. Setup: admin role, working schema, Trust Center access
-- ---------------------------------------------------------------------
USE ROLE ACCOUNTADMIN;
CREATE DATABASE IF NOT EXISTS SECURITY_LAB;
CREATE SCHEMA IF NOT EXISTS SECURITY_LAB.POLICIES;
USE SCHEMA SECURITY_LAB.POLICIES;
GRANT APPLICATION ROLE SNOWFLAKE.TRUST_CENTER_ADMIN TO ROLE ACCOUNTADMIN;

-- Demo users
-- LAB_HUMAN: a person with a password (Trust Center will track their MFA enrollment)
-- LAB_SVC:   a service account (no password allowed on SERVICE users)
CREATE USER IF NOT EXISTS LAB_HUMAN
  TYPE = PERSON
  PASSWORD = 'ChangeMe-Lab-2026!'
  MUST_CHANGE_PASSWORD = TRUE
  COMMENT = 'Securing Snowflake lab: human user';

CREATE USER IF NOT EXISTS LAB_SVC
  TYPE = SERVICE
  COMMENT = 'Securing Snowflake lab: service account';


-- ---------------------------------------------------------------------
-- 1. Network policy
-- A network rule defines trusted locations; a network policy enforces them.
-- Replace the IP range with wherever your service account connects from.
-- ---------------------------------------------------------------------
CREATE OR REPLACE NETWORK RULE SECURITY_LAB.POLICIES.ETL_SERVER_IPS
  TYPE = IPV4
  MODE = INGRESS
  VALUE_LIST = ('203.0.113.0/24')
  COMMENT = 'Trusted IPs for service accounts';

CREATE OR REPLACE NETWORK POLICY SVC_NETWORK_POLICY
  ALLOWED_NETWORK_RULE_LIST = ('SECURITY_LAB.POLICIES.ETL_SERVER_IPS')
  COMMENT = 'Service accounts can only connect from trusted IPs';

ALTER USER LAB_SVC SET NETWORK_POLICY = SVC_NETWORK_POLICY;

-- Snowflake-managed SaaS rules (Tableau, Power BI, dbt, GitHub Actions and more).
-- There are 300+, so we filter to Tableau. Add one to ALLOWED_NETWORK_RULE_LIST the same way.
SHOW NETWORK RULES LIKE 'TABLEAU%' IN SCHEMA SNOWFLAKE.NETWORK_SECURITY;


-- ---------------------------------------------------------------------
-- 2 & 3. Authentication policies
-- Humans: SSO, or a password plus required MFA
-- Service accounts: key pair only, never a password
-- ---------------------------------------------------------------------
CREATE OR REPLACE AUTHENTICATION POLICY SECURITY_LAB.POLICIES.HUMAN_MFA_POLICY
  AUTHENTICATION_METHODS = ('PASSWORD', 'SAML')
  MFA_ENROLLMENT = 'REQUIRED'
  COMMENT = 'Humans: SSO or password + MFA';

ALTER USER LAB_HUMAN SET AUTHENTICATION POLICY SECURITY_LAB.POLICIES.HUMAN_MFA_POLICY;

CREATE OR REPLACE AUTHENTICATION POLICY SECURITY_LAB.POLICIES.SVC_KEYPAIR_POLICY
  AUTHENTICATION_METHODS = ('KEYPAIR')
  COMMENT = 'Service accounts: key pair only';

ALTER USER LAB_SVC SET AUTHENTICATION POLICY SECURITY_LAB.POLICIES.SVC_KEYPAIR_POLICY;


-- ---------------------------------------------------------------------
-- 4. Trust Center: scan and read findings
-- PERSON User Strong Authentication Readiness is part of Security Essentials,
-- which is on in every account at no extra cost.
-- Results take about a minute to land. If LAB_HUMAN isn't there yet, wait and re-run.
-- ---------------------------------------------------------------------
CALL SNOWFLAKE.TRUST_CENTER.EXECUTE_SCANNER(
  'SECURITY_ESSENTIALS',
  'SECURITY_ESSENTIALS_STRONG_AUTH_PERSON_USERS_READINESS'
);

-- Latest open finding per scanner, worst first
SELECT scanner_package_name, scanner_name, severity, total_at_risk_count, end_timestamp
FROM SNOWFLAKE.TRUST_CENTER.FINDINGS
WHERE UPPER(state) = 'OPEN'
  AND total_at_risk_count > 0
QUALIFY ROW_NUMBER() OVER (PARTITION BY scanner_id ORDER BY end_timestamp DESC) = 1
ORDER BY CASE UPPER(severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END;

-- Drill in: which people are at risk, and what Trust Center suggests
SELECT e.value:entity_name::STRING AS at_risk_user,
       f.severity,
       f.suggested_action
FROM SNOWFLAKE.TRUST_CENTER.FINDINGS f,
     LATERAL FLATTEN(input => f.at_risk_entities) e
WHERE f.scanner_id = 'SECURITY_ESSENTIALS_STRONG_AUTH_PERSON_USERS_READINESS'
  AND f.total_at_risk_count > 0
QUALIFY RANK() OVER (ORDER BY f.end_timestamp DESC) = 1;


-- ---------------------------------------------------------------------
-- 5. Read the finding and verify coverage
-- LAB_HUMAN shows up as "covered by an MFA policy but not yet enrolled."
-- That's the policy working: at next login Snowflake makes them enroll in MFA,
-- and the finding clears on the next scan.
-- For stale users, Trust Center suggests: ALTER USER <user> SET DISABLED = TRUE;
-- ---------------------------------------------------------------------
SELECT ref_entity_name AS user_name, policy_kind, policy_name
FROM TABLE(SECURITY_LAB.INFORMATION_SCHEMA.POLICY_REFERENCES(ref_entity_name => 'LAB_HUMAN', ref_entity_domain => 'USER'))
UNION ALL
SELECT ref_entity_name, policy_kind, policy_name
FROM TABLE(SECURITY_LAB.INFORMATION_SCHEMA.POLICY_REFERENCES(ref_entity_name => 'LAB_SVC', ref_entity_domain => 'USER'));


-- ---------------------------------------------------------------------
-- Cleanup: removes everything this lab created
-- ---------------------------------------------------------------------
USE ROLE ACCOUNTADMIN;
ALTER USER IF EXISTS LAB_HUMAN UNSET AUTHENTICATION POLICY;
ALTER USER IF EXISTS LAB_SVC UNSET AUTHENTICATION POLICY;
ALTER USER IF EXISTS LAB_SVC UNSET NETWORK_POLICY;
DROP USER IF EXISTS LAB_HUMAN;
DROP USER IF EXISTS LAB_SVC;
DROP NETWORK POLICY IF EXISTS SVC_NETWORK_POLICY;
DROP DATABASE IF EXISTS SECURITY_LAB;
-- Optional: REVOKE APPLICATION ROLE SNOWFLAKE.TRUST_CENTER_ADMIN FROM ROLE ACCOUNTADMIN;
SHOW USERS LIKE 'LAB_%';
