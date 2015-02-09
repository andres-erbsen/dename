# `dename`

`dename` is a decentralized system that securely maps usernames to
profiles. A profile can contain any information the user wishes; for
example, it can serve as a public key infrastructure, a store of
electronic business cards, or as a domain name. By "secure", we
mean that (a) everybody sees the same profile for the same name and (b)
only the owner of a profile can modify it.  The abstraction `dename`
provides is similar NameCoin's, but `dename` does not rely on proof of
work -- instead, each client can pick a set of verifier servers which it
believes to contain at least one honest member.

## Usage

Let's say a friend of yours wishes to grant you write access to a `git`
repository on his server. However, as nobody other than the two of you
should be able to change the code, you decide to use `git` over `ssh`
with public-key authentication.

Everything seems fine, except that all ways of telling each other your
public keys seem to be lacking something. Sending them over email or
another conventional online channel would be susceptible to attack --
anybody could send an email from your address to your friend, asking to
add their key instead. Printing out the keys and handing them to each
other the next time you meet would definitely establish their
authenticity, but typing them in again would be tedious. Handing over
hashes of keys on paper, downloading the keys separately and verifying
the hashes is also a fine strategy, but neither of you is well-versed in
cryptography and you are rightfully unsure whether this convoluted
strategy would be secure. Even if it was, it would still be
inconvenient.

### Installation

	go get github.com/andres-erbsen/dename/{dnmgr/dnmgr,dnmlookup}

This requires the [`go` language toolchain](http://golang.org/).

To update an existing `dename` installation, run

	go get -u github.com/andres-erbsen/dename/{dnmgr/dnmgr,dnmlookup}

### Command line

Authorize *Alice* to control the current machine using `ssh`:

	dnmlookup alice ssh | tee -a ~/.ssh/authorized_keys

Add the [`ssh` host key] of *Alice's* machine *yummy.tld*:

	dnmlookup alice ssh-host | grep -w "^yummy.tld" | tee -a ~/.ssh/known_hosts

Add *Alice's* [OpenPGP] key to the local keyring:

	gpg --recv-keys "$(dnmlookup alice pgp)"

Encrypt a message so that only *Alice* can read it:

	gpg --armor --encrypt --recipient "$(dnmlookup alice pgp)" > message.pgp

Verify a message *Alice* signed using [`signify`]:

	signify -V -e -p <(dnmlookup alice 9881561) -s signed-message -m verified-message

Display all fields in a profile (using [protoc](https://github.com/google/protobuf/#protocol-buffers---googles-data-interchange-format)):

	dnmlookup andres | protoc --decode_raw

### Management

Create a new name-profile pair with the name *Bob*:

	dnmgr init bob # visit <https://dename.mit.edu/> first to get an invite code

Add `ssh` public keys a profile: (the `.pub` is crucial, otherwise the secret keys will be uploaded as well)

	dnmgr set bob ssh "$(cat ~/.ssh/id_*.pub)"

Add a `gpg` key to the profile (by fingerprint, the key itself is too big):

	dnmgr set bob pgp "$(gpg --fingerprint -K $KEYID | grep -im1 fingerprint\ = | tr -dc A-F0-9)"

#### Back up `~/.config/dename`

Each `dename` name is controlled by a secret key, which `dnmgr` by default
stores in `~/.config/dename`. You probably want to back it up somewhere safe (as
the secret key is just 64 bytes, I would recommend printing it out, both in hex
and QR code format). There is no way to modify a profile without having the
corresponding key. This is so because we (the `dename` server operators) would
not have any way of proving to the world that the correct user actually
contacted us and asked us to recover their name (as opposed to a third party
compelling us to do so).

### Update your profile every 6 months

If a profile stays unmodified for a year, the name will become available for
registration. This way the profiles for which the corresponding secret key is
long lost won't be cluttering the namespace forever. To make sure legitimate
users do not lose control of their profiles, lookups will start returning an
error earlier -- currently at the 6 months mark. The profile does not need to
change, any `dnmgr set` command will bump the expiration time if successful.

### Scripts

`dngpg` performs arbitrary `gpg` commands with a `dename` user's public key as
the recipient. Specifically, `dngpg <user> [args...]` is equivalent to `gpg
--always-trust --recipient 0xabcdef01 [args...]` where 0xabcdef01 is the user's
PGP key fingerprint as retrieved from `dename`. The local keyring trust state is
not modified.

`dnget <user> <filename>` looks up the URL and hash of the file from the
user's profile, downloads it and verifies that the downloaded file matches the
hash advertised on `dename`. As both current and past `dename` profiles are
public, this program can be seen as a barebones [software transparency] tool.

### Client Library

`client/` contains a Go library for interfacing with the `dename` servers.
It provides functions for registering, modifying and transferring profiles. For
POSIX userland applications, `dnmgr/` exposes the persistence layer used by the
`dnmgr` command line tool.

How `dename` works
------------------

A universally known (but not trusted) group of core servers
accept profile modification requests and pick a consistent order in
which to apply them. Independently operated verifier servers compute the
result of these operations and sign it. Clients can contact any of the
servers to look up names and be assured that unless *all* servers are
broken or colluding against them, the result is correct.

Names are allocated to users on a first-come first-serve basis.
Specifically, any user can at any time contact a core server and ask
them to "assign name N to public key P". Rate-limiting and spam
prevention is the responsibility of the core servers: currently, a
non-profit email address is required for registration. The bearer of a
name can transfer the name to another key (their own or somebody else's)
by signing the message "transfer name N to public key P'" with the old
secret key and sending it to a server. This enables key
revocations/upgrades and (domain) name sales.

When a core server receives a request, it first verifies that it is valid
(the name is available / the transfer is signed by the bearer of the
name) and forwards it to the verifiers. With some regularity, all
core servers commit to the requests they have forwarded, verifiers
handle these requests in a stable pseudo-random order, and sign the new
name assignments.

To speed up updating and signing the name assignments, the names-profile
mapping is stored in a crit-bit tree with Merkle hashing. That is, every
crit-bit node also contains the hash of its children. This way the
hash of the root node summarizes the state of all the names and can be
signed instead of the possibly large table of all names. When a client
asks for the profile associated with a name, the server also returns all
children of the nodes on the path from the root to the node storing that
name and the corresponding profile. The client can use the hashes of
these nodes to compute the root and be assured that the (name, profile)
pair is indeed present in that tree. After verifying the servers'
signatures on that root, the client can be assured that if at least
least one server is correct then the profile he saw is the same that
everybody else sees.

Contribute
----------

### Use it and report back!

We would love to hear how `dename` worked for you, and even if it really
didn't you should let us know so that we can fix the issue, saving
somebody else the trouble. Technical and non-technical feedback are
equally appreciated. To get in touch with us, use the Github issues link
on this page or [contact us](mailto:dename@mit.edu) by email.

the public mailing list
[dename-servers@mit.edu](http://mailman.mit.edu/mailman/listinfo/dename-servers)
will receive notifications about updates and issues related to the dename
utilities and the server software respectively.

### Integrate `dename` with `$YOUR_FAVORITE_APPLICATION`

`dename` is designed to be easy to integrate into other applications for a
seamless user experience. See the command line examples above for ideas --
pretty much any application that already uses secure cryptographic identifiers
can be made easier to use using `dename`, and building a new system that uses
`dename` for user management should be comparably easy.

### Run a server

The security of `dename` depends on having a diverse set of verification
servers. The following notes are provided to give you a rough idea on how to set
up an independent server.


1. Add yourself to
[dename-servers@mit.edu](http://mailman.mit.edu/mailman/listinfo/dename-servers).
2. Clone this repository and run the following command to build the server

	cd server/server && go build -v; cd ../..

3. Configure the server

		mkdir /home/dename/keys && chmod 700 /home/dename/keys
		go run utils/mkkey/mkkey.go /home/dename/keys
		go run ../chatterbox/transport/transport-keygen/main.go /home/dename/keys

	Into `~dename/denameserver.cfg`:
	
		[backend]
		DataDirectory = /home/dename/leveldb
		SigningKeyPath = /home/dename/keys/secret_key
		Listen = 0.0.0.0:8877
		[frontend]
		TransportKeyPath = /home/dename/keys/transport_secret_key
		Listen = 0.0.0.0:6263
		[server "dename.mit.edu:8877"]
		PublicKey = CiCheFqDmJ0Pg+j+lypkmmiHrFmRn50rlDi5X0l4+lJRFA==
		IsCore = true
		[server "127.0.0.1:8877"]
		PublicKey = # run `base64 /home/dename/keys/public_key` and copy here

	Run it: `./server/server/server /home/dename/denameserver.cfg`

4. Configure your client to talk to your server. Into `~/.config/dename/authorities.cfg`:

		[verifier "mit-pilot"]
		PublicKey = CiCheFqDmJ0Pg+j+lypkmmiHrFmRn50rlDi5X0l4+lJRFA==
		[verifier "my-verifier"]
		PublicKey = # run `base64 /home/dename/keys/public_key` and copy here

		[lookup "my-verifier-address:port"]
		TransportPublicKey = # run `base64 /home/dename/keys/transport_public_key` and copy here
		
		[update "dename.mit.edu:6263"]
		TransportPublicKey = 4f2i+j65JCE2xNKhxE3RPurAYALx9GRy0Pm9c6J7eDY=

5. (or if you get stuck) Email [dename@mit.edu](mailto:dename.mit.edu) and let
   us know how it went, and whether you'd like to have your server added to a
   public list of community servers (see issue #24).

[OpenPGP]: https://andreser.scripts.mit.edu/blog/2013-08-10-how-to-use-openpgp-for-email-in-1000-words/
[`ssh` host key]: http://www.rackspace.com/knowledge_center/article/rackspace-cloud-essentials-checking-a-server%E2%80%99s-ssh-host-fingerprint-with-the-web-console#Explaining
[`signify`]: http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man1/signify.1
[software transparency]: https://zyan.scripts.mit.edu/blog/software-transparency/
