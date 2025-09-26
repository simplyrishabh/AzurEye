# Contributing to AzurEye

Thank you for your interest in contributing to AzurEye! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites
- Python 3.7 or higher
- Azure CLI 2.0 or higher
- Git
- Basic understanding of Azure services and security

### Development Setup
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/simplyrishabh/AzurEye.git
   cd AzurEye
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Install Azure CLI extensions:
   ```bash
   az extension add --name logic
   az extension add --name automation
   ```

## 📝 How to Contribute

### Reporting Issues
- Use the GitHub issue tracker
- Provide detailed information about the problem
- Include steps to reproduce the issue
- Specify your environment (OS, Python version, Azure CLI version)

### Suggesting Features
- Open an issue with the "enhancement" label
- Describe the feature and its benefits
- Consider the impact on existing functionality

### Code Contributions
1. Create a feature branch from `main`
2. Make your changes
3. Test your changes thoroughly
4. Update documentation if needed
5. Submit a pull request

## 🧪 Testing

### Before Submitting
- Test your changes with different Azure services
- Verify that existing functionality still works
- Check for any new security vulnerabilities
- Ensure code follows the project's style guidelines

### Test Scenarios
- Scan different Azure services
- Test with various subscription configurations
- Verify report generation works correctly
- Check database operations

## 📋 Code Style

### Python
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Keep functions focused and small

### Comments
- Avoid obvious comments
- Explain complex logic and business rules
- Update comments when code changes

## 🔒 Security Considerations

### When Adding New Scanners
- Ensure proper error handling
- Don't expose sensitive information in logs
- Validate all inputs
- Use least-privilege access patterns

### Data Handling
- Be careful with sensitive data
- Don't store secrets in plain text
- Follow the principle of least privilege
- Consider data retention policies

## 📚 Documentation

### Code Documentation
- Add docstrings for new functions
- Update README.md for new features
- Include examples in documentation
- Keep installation instructions current

### User Documentation
- Update user-facing documentation
- Add screenshots for UI changes
- Provide clear examples
- Include troubleshooting information

## 🐛 Bug Fixes

### Priority Levels
1. **Critical**: Security vulnerabilities, data loss
2. **High**: Core functionality broken
3. **Medium**: Feature not working as expected
4. **Low**: Minor issues, cosmetic problems

### Fix Process
1. Reproduce the issue
2. Identify the root cause
3. Implement a fix
4. Test the fix thoroughly
5. Update tests if needed

## 🚀 New Features

### Feature Requirements
- Must align with project goals
- Should not break existing functionality
- Must include proper error handling
- Should be well-documented

### Implementation Process
1. Discuss the feature in an issue
2. Get approval from maintainers
3. Implement the feature
4. Add tests
5. Update documentation
6. Submit pull request

## 📞 Getting Help

### Communication Channels
- GitHub Issues for bugs and features
- GitHub Discussions for questions
- Pull Request comments for code review

### Response Times
- Critical issues: Within 24 hours
- Regular issues: Within 1 week
- Feature requests: Within 2 weeks

## 🏆 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AzurEye! 🎉
