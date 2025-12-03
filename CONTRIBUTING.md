# Contributing to PURPLE HAT

We welcome contributions from the security community! This guide will help you get started.

## Code of Conduct

- Be respectful and inclusive
- Report security vulnerabilities privately
- Focus on improving the tool for everyone

## Getting Started

### Prerequisites
- Python 3.8+
- Git
- Virtual environment tools

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install code quality tools
pip install black flake8 mypy pytest pytest-cov
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bugfix-name
```

### 2. Make Your Changes

- Follow PEP 8 style guide
- Add docstrings to functions and classes
- Add type hints where appropriate
- Include comments for complex logic

### 3. Code Quality

```bash
# Format code
black .

# Check code style
flake8 .

# Type checking
mypy core/ modules/ ui/ utils/

# Run tests
pytest tests/

# Check coverage
pytest --cov=. tests/
```

### 4. Create Tests

Add tests for new features in the `tests/` directory:

```python
# tests/test_feature.py
import pytest
from feature_module import Feature

def test_feature_basic():
    feature = Feature()
    assert feature.method() == expected_result

def test_feature_edge_case():
    feature = Feature()
    with pytest.raises(ValueError):
        feature.invalid_input()
```

### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: Add new feature description

- Detailed explanation of changes
- Key improvements
- Breaking changes (if any)
"
```

**Commit message format:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes
- `refactor:` - Code refactoring
- `test:` - Test additions/modifications
- `chore:` - Build/dependency updates

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots (if applicable)

## Areas for Contribution

### High Priority

- [ ] Additional injection methods (LFI, XXE improvements)
- [ ] Advanced WAF bypass techniques
- [ ] Machine learning-based detection
- [ ] Enhanced reporting (PDF, DOCX export)
- [ ] Parallel distributed scanning

### Medium Priority

- [ ] API improvements and versioning
- [ ] Database integration (SQLite, PostgreSQL)
- [ ] Authentication module enhancements
- [ ] Performance optimizations
- [ ] UI/UX improvements

### Low Priority

- [ ] Documentation improvements
- [ ] Example payloads
- [ ] Tutorial videos
- [ ] Blog posts
- [ ] Community guides

## Module Development Guide

### Creating a New Module

```python
# modules/new_feature/new_module.py

class NewModule:
    def __init__(self):
        self.name = "New Feature"
        self.description = "Description of the new feature"
        self.version = "1.0.0"
    
    def execute(self, target, **kwargs):
        """
        Execute the module
        
        Args:
            target: Target URL or host
            **kwargs: Additional parameters
            
        Returns:
            dict: Results dictionary
        """
        results = {
            'success': True,
            'findings': [],
            'metadata': {
                'module': self.name,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        # Implementation here
        
        return results
```

### Integration with Engine

```python
# Add to core/engine.py
from modules.new_feature.new_module import NewModule

self.modules["new_category"]["new_feature"] = NewModule()
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test

```bash
pytest tests/test_module.py::test_function -v
```

### With Coverage

```bash
pytest --cov=. --cov-report=html tests/
```

## Documentation

### Docstring Format

```python
def function(param1: str, param2: int) -> dict:
    """
    Brief description of function
    
    Longer description if needed, explaining behavior
    and any important details.
    
    Args:
        param1 (str): Description of param1
        param2 (int): Description of param2
        
    Returns:
        dict: Description of return value
        
    Raises:
        ValueError: Description of when this is raised
        
    Example:
        >>> result = function("test", 42)
        >>> print(result)
        {'success': True}
    """
    pass
```

### Update Documentation

- Update README.md for major features
- Add docstrings to new functions
- Update API documentation
- Include examples and usage

## Reporting Issues

### Security Vulnerabilities

Please report security issues privately to security@purplehat.io

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Bug Reports

When reporting bugs, include:
- Python version and OS
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages/traceback
- Screenshots (if applicable)

### Feature Requests

When requesting features:
- Clear description of feature
- Use case and benefits
- Examples or references
- Proposed implementation (if you have ideas)

## Pull Request Process

1. Update documentation and tests
2. Ensure all tests pass: `pytest`
3. Check code quality: `black . && flake8 .`
4. Update CHANGELOG.md
5. Create PR with clear description
6. Address review comments
7. Ensure CI/CD passes

## Style Guidelines

### Python Style (PEP 8)

```python
# Good
class SecurityTester:
    """Main security testing class."""
    
    def __init__(self, config: dict):
        self.config = config
        self.results = []
    
    def run_scan(self, target: str) -> dict:
        """Execute security scan on target."""
        results = self._scan_target(target)
        return results
    
    def _scan_target(self, target: str) -> dict:
        """Internal method to scan target."""
        pass


# Avoid
class SecTest:
    def __init__(self,c):
        self.c=c;self.r=[]
    def scan(self,t):
        return self.__scan(t)
    def __scan(self,target):
        pass
```

### Naming Conventions

- Classes: `PascalCase`
- Functions/Methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`
- Protected methods: `_single_leading_underscore`

### Comments and Docstrings

- Write clear, concise comments
- Explain WHY, not WHAT
- Keep docstrings up to date
- Use type hints

## Release Process

1. Update version in `setup.py`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v2.0.0`
4. Push tag: `git push origin v2.0.0`
5. Create GitHub release with notes
6. Build and publish to PyPI (maintainers)

## Resources

- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Questions?

- Check existing issues and discussions
- Review documentation
- Open a discussion for questions
- Contact maintainers

Thank you for contributing to PURPLE HAT! 🙏
