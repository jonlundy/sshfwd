-include Makefile.local.mk

export SSH_LISTEN?=:2222
export SSH_HOSTKEYS?=hostkeys
export SSH_AUTHKEYS?=authkeys


run:
	go run .

genkeys:
	mkdir -p $(SSH_HOSTKEYS)
	ssh-keygen -q -N "" -t rsa -b 4096 -f $(SSH_HOSTKEYS)/rsa
	ssh-keygen -q -N "" -t ecdsa       -f $(SSH_HOSTKEYS)/ecdsa
	ssh-keygen -q -N "" -t ed25519     -f $(SSH_HOSTKEYS)/ed25519
	rm -f $(SSH_HOSTKEYS)/*.pub
