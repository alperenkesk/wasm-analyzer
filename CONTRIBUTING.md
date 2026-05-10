# Contributing to WASM Analyzer

Thank you for your interest in contributing to WASM Analyzer! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How Can I Contribute?

### Reporting Bugs

Before submitting a bug report:
1. Check the [issue tracker](../../issues) to avoid duplicates
2. Update to the latest version to confirm the issue persists
3. Include your environment details (Burp Suite version, Java version, OS)

**Bug reports should include:**
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Screenshots or log output (if applicable)

### Suggesting Features

Feature requests are welcome! Please:
1. Check existing issues to avoid duplicates
2. Clearly describe the feature and its use case
3. Explain why this would benefit the community

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** — use clean, well-documented code
3. **Test your changes** — ensure the extension loads correctly in Burp Suite
4. **Update documentation** — if adding new features, update the README
5. **Submit a clear PR description** explaining your changes

## Development Setup

### Prerequisites
- Java 17 or later
- Maven 3.6+
- Burp Suite Professional or Community (2023.1+)

### Building

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/wasm-analyzer.git
cd wasm-analyzer

# Build
mvn clean package

# The JAR will be at: target/wasm-analyzer-*.jar
```

### Loading into Burp

1. Open Burp Suite → **Extender** → **Add**
2. Select the generated JAR
3. Test your changes

## Coding Standards

- Write clear, descriptive variable and method names
- Add JavaDoc comments for public methods
- Keep methods focused and single-purpose
- Follow existing code style and conventions

## Commit Message Guidelines

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example:**
```
feat(scanner): add client bypass detection

Add rules to detect functions like is_admin, has_access that
could be exploited for client-side authentication bypass.

Closes #123
```

## License

By submitting a contribution, you agree that your contribution will be licensed under the MIT License.

## Questions?

Feel free to [open an issue](../../issues/new) if you have any questions or need help.