# Contributing to Nerva

Thank you for your interest in contributing to Nerva! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.18 or higher
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/praetorian-inc/nerva.git
cd nerva

# Build the project
go build ./cmd/nerva

# Run tests
go test ./...
```

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/praetorian-inc/nerva/issues) to avoid duplicates
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Go version and OS information

### Suggesting Features

1. Open an issue describing the feature
2. Explain the use case and benefits
3. Wait for feedback before implementing

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `go test ./...`
6. Run linting: `go vet ./...`
7. Commit with clear messages
8. Push and create a Pull Request

## Adding a New Protocol Plugin

Nerva uses a plugin architecture for service detection. To add a new protocol:

1. Create a new directory under `pkg/plugins/services/`
2. Implement the `Plugin` interface
3. Add tests in `*_test.go`
4. Register the plugin in `pkg/plugins/plugins.go`

### Plugin Structure

```go
package myprotocol

import (
    "github.com/praetorian-inc/nerva/pkg/scan"
)

type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target scan.Target) (*scan.Result, error) {
    // Detection logic here
}

func (p *Plugin) PortPriority(port uint16) bool {
    return port == 1234 // Default port for this protocol
}

func (p *Plugin) Name() string {
    return "myprotocol"
}

func (p *Plugin) Type() scan.TransportProtocol {
    return scan.TCP
}
```

## Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Add comments for exported functions
- Keep functions focused and testable

## Testing

- All new features require tests
- Run the full test suite before submitting PRs
- Use the `pkg/test` utilities for integration tests

## Questions?

Open an issue or reach out to the maintainers.
