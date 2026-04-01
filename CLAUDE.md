# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`nap-java` is the standalone Java NAP v2 library extracted from gateway session-management code.

## Build Commands

```bash
mvn -q test
mvn -q verify
```

## Module Structure

```text
nap-java/
├── nap-core
├── nap-server
├── nap-jdbc
├── nap-client
├── nap-spring
└── nap-it
```

## Design Notes

- Keep the core modules framework-agnostic.
- Spring-specific behavior belongs in `nap-spring`.
- Treat challenge/session semantics as protocol contracts.
