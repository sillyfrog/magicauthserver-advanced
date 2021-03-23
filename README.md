# Magic Auth Server - Advanced

A more authentication server to work with my [Magic Reverse Proxy](https://github.com/sillyfrog/magicreverseproxy), including support for two factor auth with [Authy](https://authy.com/)

A `Dockerfile` is included, this pulls in all of the dependencies via pip. This version stores details in a Postgres Database, and caches keys/cookies in Redis.

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

## Other configuration options

These can be set by either using docker secrets or environment variables. If using docker secrets, they should be all lower case, and environment variables all upper case. The headings below all assume environment variables, and are upper case. Docker secrets are tried before environment variables.

### COOKIE_DOMAIN

If you have the `COOKIE_DOMAIN` set to `example.com`, then you could have a number of subdomains, such that when you authenticate with 1 domain, you are authenticated with them all, eg:

- index.example.com
- first.example.com
- more.example.com

### COOKIE_SECURE

If set to "True", then the secure flag will be set on any cookies that are sent to the client. This is recommended for production.

### MY_DOMAINS

A comma separated list of domains which point to the actual server instance. These domains, if visited in a browser, allow for user management (assuming you have administration rights), or for a user to reset their password. A user can also manually navigate to `/magicauth/users/self` at any authenticated domain to manage their own account (with an appropriate path redirect configured in Traefik).

### TRUSTED_NETS

A comma separated list of IP networks that are trusted and will _not_ required authentication. If a user visits from one of these listed IP networks, they will instantly be granted access. This uses the `X-Forwarded-For` header, so ensure the upstream proxy correctly filters and sets this header if using the feature. The network format is anything supported by the Python 3 `ipaddress.ip_network` function (with strict set to `False`). For example, `10.0.0.0/8`. IPv6 should also work, but has not been tested.

### HOME_PATH

Optional. This is the path that you want the "Home" link to point to. By default it will go to "/". You can put in a full URL if desired.

### RECAPTCHA_SITE_KEY / RECAPTCHA_SECRET_KEY

Optional. If set, will present the user with a [Google reCAPTCHA v2](https://developers.google.com/recaptcha) at login time. When setting up users, there is also an option to "Allow reCAPTCHA only login" - this means you can selectively allow users to login without 2 Factor Auth. However for this to work, the `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` _must_ be set. To create the keys, visit: http://www.google.com/recaptcha/admin

## authform.jinja

The included `authform.jinja` in the templates directory is a simple username and password from, that sends the auth details back using AJAX. The implementation is this way because of how nginx does its proxying/caching with the auth server. Using a traditional POST caused all sorts of weird reliability issues (this could have been anything from Docker buffer sizes to shell buffers to something else). This method worked well for me, so it stayed.

That said, the HTML/CSS of the from can be totally customized as you require.

## Swarm Example

See the included `docker-compose.yml` for an example that can run in a Docker Swarm.
