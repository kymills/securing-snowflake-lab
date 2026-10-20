# Securing Snowflake: Network Policies, Auth Policies, and Trust Center

Hands-on lab code for the Snowflake Activation Webinar.

## Slides

The webinar deck: [`securing-snowflake-slides.pdf`](securing-snowflake-slides.pdf)

## What you'll build

1. Two demo users: a human (`PERSON`) and a service account (`SERVICE`)
2. A network policy that locks the service account to trusted IPs
3. Authentication policies: MFA for humans, key pair only for services
4. A Trust Center scan and a real finding
5. A check that every user has the right policies attached

## How to run

1. Sign in to Snowsight as a user with the `ACCOUNTADMIN` role.
2. Open a new SQL worksheet.
3. Copy [`securing_snowflake_lab.sql`](securing_snowflake_lab.sql) into the worksheet.
4. Run it one section at a time, top to bottom.
5. Run the **Cleanup** section at the end to remove everything.

## Notes

- All policies are applied at the **user level**, so you can't lock yourself out of your account.
- Trust Center scan results take about a minute to appear. If the findings query is empty, wait and run it again.
- The Trust Center scanner used here is part of Security Essentials, which is on in every account at no extra cost.
- Use a trial or sandbox account if you have one.
