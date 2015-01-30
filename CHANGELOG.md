- `4b56a988ef41cd33e4a4dc2862a007451bc5d4dd` Thu Jan 29 20:36:11 2015 -0500
    - The client-server connections no longer use TLS (but `dename.mit.edu` runs
	  a backwards-compatibility proxy).
    - Multiple flaky tests were fixed, along with a potential shutdown deadlock. 
	- Non-leader servers now explicitly reject modification requests instead of
	  letting the client hang.
