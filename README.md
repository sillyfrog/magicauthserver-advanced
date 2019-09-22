# Magic Auth Server - Advanced

A more authentication server to work with my [Magic Reverse Proxy](https://github.com/sillyfrog/magicreverseproxy), including support for two factor auth with [Authy](https://authy.com/)

A `Dockerfile` is included, this pulls in all of the dependancies via pip. This version stores details in a Postgres Database, and caches keys/cookies in Redis.

## Database setup

The server requires access to a Postgres database for the user management, this can also run in Docker.

To create the initial database, connect into the Postgres docker container, and create the database and a DB user, such as the following (if not using the Postgres provided method):
```
/# psql template1 postgres
psql (11.5 (Debian 11.5-1.pgdg90+1))
Type "help" for help.

template1=# CREATE DATABASE users;
CREATE DATABASE
template1=# CREATE USER users WITH ENCRYPTED PASSWORD 'secret';
CREATE ROLE
template1=# GRANT ALL PRIVILEGES ON DATABASE users TO users;
GRANT
```

Once the database has been created, update the environment/secret in the Auth Server container to match the URI. When the service starts for the first time it will create the required tables. For example, the secret to connect to the DB in a Swarm would be:
```
postgresql+psycopg2://users:secret@postgres/users
```

Then you can start the container, and create your first user:
```
$ ./authserver -a
Username: someone
Password:
```
This is designed to run in Docker, and the configuration is read from the environment and/or Docker Secrets. You should `exec` into the container to run the above.

This will put the user details into the DB.

The first time a user goes to login, they must configure the OTP in Authy (or similar app) and login. Once this is done, the key/hash is saved in the DB. The user will be displayed a QR code to scan with their phone.

Once at least one user account (username and password) has been created, you can login with the auth server. The domain for cookies that are set must be configured. The idea is that the cookie is set on your root domain, so the authentication flows to all other subdomains. See below for how to configure the container.

If you have the `COOKIE_DOMAIN` set to `example.com`, then you could have a number of subdomains, such that when you authenticate with 1 domain, you are authenticated with them all, eg:
 - index.example.com
 - first.example.com
 - more.example.com

## authform.html

The included `authform.html` in the templates directory is a simple username and password from, that sends the auth details back using AJAX. The implementation is this way because of how nginx does its proxying/caching with the auth server. Using a traditional POST caused all sorts of weird reliability issues (this could have been anything from Docker buffer sizes to shell buffers to something else). This method worked well for me, so it stayed.

That said, the HTML/CSS of the from can be totally customised as you require.

## Swarm Example

See the included `docker-compose.yml` for an example that can run in a Docker Swarm.


