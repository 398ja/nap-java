<!--
  Sync Impact Report
  ==================
  Version change: 0.0.0 -> 1.0.0
  Modified principles: N/A (initial adoption)
  Added sections:
    - I. Protocol-First Design
    - II. Module Boundary Discipline
    - III. Minimal Dependencies
    - IV. Testing Discipline
    - V. Secure Coding
    - VI. Code Quality & Simplicity
    - Development Workflow
    - Governance
  Removed sections: None
  Templates requiring updates:
    - .specify/templates/plan-template.md — ✅ compatible
    - .specify/templates/spec-template.md — ✅ compatible
    - .specify/templates/tasks-template.md — ✅ compatible
  Follow-up TODOs: None
-->

# NAP Java Constitution

## Core Principles

### I. Protocol-First Design

This project implements the Nostr Authentication Protocol (NAP) v2
as a standalone, multi-module Java library. Every module MUST
serve the protocol's authentication and session-management
contracts.

- The `nap-core` module MUST contain only protocol types,
  validation logic, and data contracts — no framework coupling
- Challenge and session semantics are protocol contracts; their
  structure MUST NOT be altered to accommodate a specific
  framework or integration
- Each module MUST have a single, well-defined responsibility:
  core types (`nap-core`), server logic (`nap-server`), JDBC
  persistence (`nap-jdbc`), client SDK (`nap-client`), Spring
  adapter (`nap-spring`), integration tests (`nap-it`)
- New protocol features MUST be defined in `nap-core` before
  being consumed by other modules

**Validation gate**: Before adding code, ask: "Does this serve
the NAP v2 protocol contract?" If it is framework glue, it
belongs in an adapter module, not core.

### II. Module Boundary Discipline

The multi-module structure enforces strict separation of concerns.
Dependency direction MUST flow inward toward `nap-core`.

- `nap-core` MUST NOT depend on any other nap module
- `nap-server` and `nap-client` MUST depend only on `nap-core`
- `nap-jdbc` MUST depend only on `nap-core` and standard JDBC
  APIs
- `nap-spring` MUST contain all Spring Boot and Spring Framework
  dependencies; no other module may reference Spring classes
- `nap-it` is the only module permitted to depend on all other
  modules (for integration testing)
- Cross-module APIs MUST be defined as interfaces in `nap-core`
  with implementations in the appropriate module

### III. Minimal Dependencies

Dependencies MUST be kept to the absolute minimum required for
each module's purpose.

- Transitive dependency bloat MUST be avoided; mark dependencies
  `<optional>true</optional>` when they are needed only by a
  subset of consumers
- Versions MUST be managed via the `imani-bom` parent POM
- All dependency and plugin versions in `pom.xml` MUST be
  declared as `<properties>` entries; inline version literals
  in `<dependency>` or `<plugin>` blocks are prohibited
- New compile-scope dependencies MUST be justified in the PR
  description with a rationale for why the functionality cannot
  be achieved without them
- MUST NOT introduce logging implementations; only `slf4j-api`
  is permitted in library modules

### IV. Testing Discipline

All code MUST meet the following testing standards:

- **Unit tests** (`*Test.java`): Run via `mvn -q test`; every
  public method MUST have at least one test
- Tests MUST use JUnit Jupiter and AssertJ
- Tests MUST exercise realistic scenarios with concrete inputs
  and expected outputs
- New features MUST include tests before merge
- Tests MUST be fast: no network calls, no file I/O, no sleeps
  (except in `nap-it` integration tests)
- Edge cases (null inputs, empty collections, boundary values)
  MUST be covered for validation utilities
- Tests MUST follow the Arrange-Act-Assert (AAA) pattern: set up
  inputs, perform the action under test, then assert outcomes —
  each section clearly separated with no interleaving
- Integration tests in `nap-it` MUST verify cross-module
  contracts and protocol round-trips

### V. Secure Coding

All code MUST follow secure coding practices. This is critical
for an authentication protocol library.

- Input validation at system boundaries (public API methods)
- No secrets in code, configs, or commits
- Cryptographic operations MUST use well-established libraries
  (standard JDK or BouncyCastle)
- OWASP Top 10 vulnerabilities are blocking defects
- Challenge generation MUST use cryptographically secure random
  sources
- Session tokens MUST be unpredictable and time-bounded
- Nostr event signature verification MUST reject malformed or
  expired events

### VI. Code Quality & Simplicity

- YAGNI: do not add features, abstractions, or error handling
  beyond what the task requires
- No speculative abstractions; three similar lines are better
  than a premature helper
- Prefer unchecked exceptions with context (operation + failure
  type) over checked exceptions
- Validate only at public API boundaries; trust internal code
- Keep methods short and focused; extract only when reuse is
  real, not hypothetical

## Development Workflow

- **Build command**: `mvn -q test` MUST pass before committing;
  `mvn -q verify` for full integration test suite
- **Commits**: Conventional Commits format:
  `feat(scope):`, `fix(scope):`, `docs(scope):`, etc.
- **Versions**: Managed in root `pom.xml`; aligned with
  `imani-bom`
- **Branching**: Feature branches off `main`; PRs target `main`
- **Code review**: All PRs require review; dependency additions
  MUST be justified

## Governance

This constitution is the authoritative source of project
standards. It supersedes ad-hoc practices and informal
conventions.

- **Amendments**: Any change to this constitution MUST be
  documented with rationale, reviewed by a maintainer, and
  reflected in the version below
- **Versioning**: MAJOR for principle removals/redefinitions,
  MINOR for new principles or material expansions, PATCH for
  clarifications and wording fixes
- **Compliance**: All PRs and code reviews MUST verify adherence
  to these principles; violations are blocking
- **Runtime guidance**: See `CLAUDE.md` for build commands and
  design notes

**Version**: 1.0.0 | **Ratified**: 2026-04-01 | **Last Amended**: 2026-04-01
