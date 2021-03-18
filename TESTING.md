# Testing

## HSM Notes

If you are running SafeNet's DPoD, then cd to the base directory and source the setenv file.

If you want to run tests in an IDE then source DPoD in a shell and start the IDE from the same shell session.

## Makefile Command Line Tests

Test the HSM connection where the conf is loaded in from conf/config-safenet.hcl

`make test hsmconnection`

`make test pathrolecreate`

`make test pathsetcrlconfig`

`make test pathfetchcrl`

`make test pathsetsignedintermediate`

`make test pathgenerateroot`

`make test pathgenerateintermediate`

`make test pathdeleteroot`
