# NAP Java

`nap-java` is the standalone Java implementation of the NAP v2 server/client library stack.

## Modules

- `nap-core`
- `nap-server`
- `nap-jdbc`
- `nap-client`
- `nap-spring`
- `nap-it`

## Build

```bash
mvn -q test
mvn -q verify
```

## Scope

- framework-agnostic NAP types and validation
- server-side session and challenge handling
- JDBC-backed stores
- Spring integration module
