# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2025-01-20
- Update macOS build targets

## [0.1.3] - 2025-01-20
- Update PyPI release process

## [0.1.2] - 2025-01-19

### Added
- `SchemaFragment` class for modular schema composition
- `Schema.from_schema_fragments()` method to combine multiple schema fragments into a complete schema
- `CedarSchema.into_schema()` method for converting Pydantic schema models to Rust `Schema`
- `CedarSchema.into_schema_fragment()` method for converting Pydantic schema models to `SchemaFragment`

## [0.1.1] - 2025-01-18

### Changed
- Package dependency version constraints for better compatibility
- Updated macOS build target to latest version

### Fixed
- CODEOWNERS file added for better repository maintenance

## [0.1.0] - 2025-01-11

### Added
- Initial release of Cedar Python bindings
- Policy evaluation with `Authorizer`, `Request`, `Response`
- Schema validation for policies, entities, and requests
- Pydantic models for programmatic schema building (`cedar.schema`)
- Formal verification via cedar-lean-cli (`cedar.lean`)
- MCP server and CLI tools
