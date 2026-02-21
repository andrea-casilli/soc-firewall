# Contributing to SOC Firewall

First off, thank you for considering contributing to SOC Firewall! It's people like you that make this project great.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to see if the problem has already been reported. When you create a bug report, include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples (commands, configuration, logs)
- Describe the behavior you observed and why it's a problem
- Include your environment details (OS, Python version, deployment method)

**Bug Report Template** is available in `.github/ISSUE_TEMPLATE/bug_report.md`

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a step-by-step description of the suggested enhancement
- Explain why this enhancement would be useful
- List any alternative solutions you've considered

**Feature Request Template** is available in `.github/ISSUE_TEMPLATE/feature_request.md`

### Pull Requests

- Fill in the required pull request template
- Follow the Python style guide (Black, isort, flake8)
- Include appropriate tests
- Update documentation
- End all files with a newline
- Make sure all tests pass

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/soc-firewall.git
cd soc-firewall

# Add upstream remote
git remote add upstream https://github.com/original/soc-firewall.git
