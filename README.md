# sshfwd

This is a reverse forward service that uses SSH as the transport. It works similar to ngrok or localtunnel.me.

You run the service on a internet addressible host and ssh to it. Using ssh remote forwards (ie. ssh -R) the port on the remote host will be forwared to
the configured port on your local machine.

on Remote host:

```sh
$ make genkeys  # generate the services host keys.
$ SSH_HOSTKEYS=hostkeys SSH_LISTEN=:2222 sshfwd   # run service on port 2222
```

on your local machine:

```sh
$ ssh -T remote.example.com -p 2222 -R 0.0.0.0:1234:localhost:3000
```

now if you access `remote.example.com:1234` it will be the same as accessing `localhost:3000`

# Pubkeys

if the env variable `SSH_AUTHKEYS` is set it will require that the client authenticates with one of the keys in the `SSH_AUTHKEYS` directory.

```sh
$ SSH_LISTEN=:2222 SSH_HOSTKEYS=hostkeys SSH_AUTHKEYS=authkeys sshfwd
```
