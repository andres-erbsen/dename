#!/bin/bash
rundir=$(realpath "$1")
if [ ! -d "$rundir" ]; then
	echo "Directory \"$rundir\" does not exist." >&2
	exit 1
fi
mkauthority > "$rundir/ca.cert.pem" 2> "$rundir/ca.secret.pem"
dd if=/dev/urandom bs=32 count=1 > "$rundir/invitekey" 2>/dev/null
for i in $(seq 1 "$2"); do
	dir="$rundir/$i"
	mkdir -p "$dir"
	mkkey > "$dir/pk" 2> "$dir/sk"
	mkcert "$rundir/ca.cert.pem" "$rundir/ca.secret.pem" 127.0.0.1 > "$dir/server.crt.pem" 2>"$dir/server.key.pem"
		echo -e "[backend]\nDataDirectory = $dir\nSigningKeyPath = $dir/sk\nListen = 127.0.0.1:198$i\n\n[frontend]\nInviteKeyPath = $rundir/invitekey\nTLSCertPath = $dir/server.crt.pem\nTLSKeyPath=$dir/server.key.pem\nListen = 127.0.0.1:144$i\n" > "$dir/denameserver.cfg"
done
echo -e "[freshness]\nThreshold = 15s\nNumConfirmations = $2\n" > "$rundir/dnmclient.cfg"
for i in $(seq 1 "$2"); do
	for j in $(seq 1 "$2"); do
		echo -e "[server \"127.0.0.1:198$i\"]\nPublicKey = $(base64 ${rundir}/$i/pk)\nIsCore = true\n" >> "$rundir/$j/denameserver.cfg"
	done
	echo -e "[server \"127.0.0.1:144$i\"]\nPublicKey = $(base64 ${rundir}/$i/pk)\nTimeout = 14s\nTLSCertFile = $rundir/ca.cert.pem\n" >> "$rundir/dnmclient.cfg"
done
