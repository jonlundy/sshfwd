# sshfwd

This is a reverse proxy service that uses SSH as the transport. It works similar to ngrok or localtunnel.me.

You run the service on a internet addressible host and ssh to it. Using ssh remote forwards (ie. ssh -R) the port on the remote host will be forwared to
the configured port on your local machine.

on Remote host:

```sh
$ make genkeys  # generate the services host keys.
$ SSH_HOSTKEYS=hostkeys SSH_LISTEN=:2222 SSH_DOMAIN=example.com sshfwd   # run service on port 2222
```

For best results place this behind a TLS termination that has a wildcard certificate and CNAME for `*.yourdomain.com`


on your local machine have a ssh private and public key available:

```sh
$ export LOCAL_PORT=3000; export PRIV_KEY=~/.ssh/id_ed25519; sh -c "$(shell http --form POST :2222 pub=@$(PRIV_KEY).pub)"
```

This will setup a reverse proxy on the example host that you can then use to access the local port. It will print a name unique to your ssh key.

```sh
$ http GET romeo-nine-lake.example.com:2222
```

All accesses to the proxy will have the HTTP request printed out to the ssh connection.

```
GET /connect HTTP/1.1
Host: romeo-nine-lake.example.com
Accept: */*
User-Agent: curl/7.64.1
X-Forwarded-Host: romeo-nine-lake.example.com
X-Origin-Host: [::1]:7000
```
