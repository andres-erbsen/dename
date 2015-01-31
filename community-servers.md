# Community-run `dename` servers

### `dename.mit.edu`

The pilot server, run by the people who started the project.  Used by default
when no configuration file is provided. Should probably accept signatures from
all servers listed [here](github.com/andres-erbsen/dename/tree/master/community-servers.md).
Currently the only server that can handle updates.

- Accepts signatures: `dename.alokat.org`
- Requires signatures: (none)
- Contact: PGP: `CFCA 4540 99B1 6042 F832 A708 4A33 C134 D6C4 7A84`, `dename`: `andres`
- Config entries:

		[verifier "pilot"]
		PublicKey = CiCheFqDmJ0Pg+j+lypkmmiHrFmRn50rlDi5X0l4+lJRFA==
		[update "dename.mit.edu:6263"]
		TransportPublicKey = 4f2i+j65JCE2xNKhxE3RPurAYALx9GRy0Pm9c6J7eDY=
		[lookup "dename.mit.edu:6263"]
		TransportPublicKey = 4f2i+j65JCE2xNKhxE3RPurAYALx9GRy0Pm9c6J7eDY=


### `dename.alokat.org`

- Accepts signatures: `dename.mit.edu`
- Requires signatures: `dename.mit.edu`
- Contact: <https://github.com/alokat>

		[verifier "alokat"]
		PublicKey = CiD6CFKBpG54dG3OMx6PJ58z5rlNFK24Dx2HMpR7urHIVA==
		[lookup "dename.alokat.org:6263"]
		TransportPublicKey = IoEJsVcspYNiuymi+JMpfkL1usDy482qE8V4aGvKrkY=
