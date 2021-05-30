# BookStack LDAP provisioning command

Provision user accounts in BookStack from a LDAP server.

This is particularly useful in conjunction with an SSO setup (either SAML2 or LDAP), so the user database is kept in sync with the LDAP database at all times: users exist even if they haven't logged in for the first time, names and emails are updated when they change and deleted accounts are deleted on BookStack too.

## Installation

1. Drop LdapProvision.php into the `app/Console/Commands` directory in your BookStack Installation
2. Add env vars definitions to .env (see below)
3. `php artisan bookstack:ldap-provision`
4. Make a cron job, systemd timer or something to run that command every e.g. 15 minutes.

With the official docker-compose you can use `docker-compose run app php artisan bookstack:ldap-provision`.

## env vars

TODO: write this section

