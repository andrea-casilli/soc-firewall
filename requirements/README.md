# SOC Firewall Requirements Management

This directory contains Python package requirements organized by environment.

## File Structure

- `base.txt` - Common dependencies for all environments
- `production.txt` - Production-specific dependencies
- `development.txt` - Development and testing tools
- `ci.txt` - Continuous integration dependencies

## Usage

### Production Installation

```bash
# Install production dependencies
pip install -r requirements/production.txt

# Or use the root requirements.txt (defaults to production)
pip install -r requirements.txt

Development Installation
# Install all dependencies including dev tools
pip install -r requirements/development.txt

# Set environment variable to use development requirements
export REQUIREMENTS_ENV=development
pip install -r requirements.txt

CI/CD Installation
# Install CI-specific dependencies
pip install -r requirements/ci.txt
