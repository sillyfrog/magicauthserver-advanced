# Magic Auth Server - Advanced

A more authentication server to work with my [Magic Reverse Proxy](https://github.com/sillyfrog/magicreverseproxy), including support for two factor auth with [Authy](https://authy.com/)

A `Dockerfile` is included, this pulls in all of the dependancies via pip. This version stores details in a Postgres Database, and caches keys/cookies in Redis.

Initially, you will need to add an admin username and password, this is done by running it with `-a`, eg:
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

The included `authform.html` in the templates directory is a simple username and password from, that sends the auth details back using AJAX. The implementation is this way because of how nginx does it proxying/caching with the auth server. Using a traditional POST caused all sorts of weird reliability issues (this could have been anything from Docker buffer sizes to shell buffers to something else). This method worked well for me, so it stayed.

That said, the HTML/CSS of the from can be totally customised as you require.

## Docker Configuration

# XXX Configurations...

If running in docker, build the image first:
```
docker build . -t authserver
```

Then run it with something like (note the `templates` is optional):
```
docker run --name authserver -d -p 80:80 -e "DOMAIN=example.com" -v /etc/localtime:/etc/localtime:ro -v /path/to/proxylogins:/proxylogins:ro -v /path/to/otpkeys:/otpkeys -v /path/to/templates:/templates
```



