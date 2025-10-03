# 🤝 Contributing Guidelines

[![Hacktoberfest 2025](https://img.shields.io/badge/Hacktoberfest-2025-orange.svg)](https://hacktoberfest.com)

Thank you for your interest in contributing to **PhantomCore**! 🚀 This DNS-layer security and privacy gateway project thrives because of contributors like you who bring improvements in code, documentation, testing, and design.

## 🎃 Hacktoberfest 2025

We're participating in Hacktoberfest 2025! Here's how you can help:

### Beginner-Friendly Tasks
- 📖 Improve documentation and setup guides
- 🎨 Add diagrams to explain concepts
- ✅ Write test cases
- 🐛 Fix small bugs

### For Experienced Contributors
- 🏗️ Implement new features
- 🚀 Optimize performance
- 🔧 Enhance configuration options
- 📊 Add monitoring capabilities

---

## 🚀 Getting Started

1. **Fork the repository** and create a new branch from `main`.
2. **Find or open an issue** that you would like to work on.
3. **Request assignment** on the issue before starting work to avoid duplication.
4. **Show progress** by opening a draft PR.
5. When ready, convert your PR to “Ready for Review.”

---

## 📜 Contribution Policies

* **Assignments:** If you are assigned an issue but show no progress within **24–48 hours**, it may be unassigned to allow others to contribute.
* **One Issue at a Time:** Please work on one issue at a time unless maintainers approve otherwise.
* **Draft PRs:** Use draft PRs to indicate ongoing work.
* **Inactive PRs:** PRs without activity for **7+ days** may be closed or reassigned.
* **Communication:** Keep interactions professional, respectful, and collaborative.
* **Code Quality:** Follow idiomatic Go practices (if coding), ensure clarity, and add tests where appropriate.
* **Commit Messages:** Use concise, descriptive messages, e.g., `fix: handle null pointer in DNS resolver`.

---

## 🌐 Types of Contributions

### 💻 Code Contributions
* **Features:** DNS filtering enhancements, policy engine improvements, upstream management
* **Bug Fixes:** Resolver issues, configuration problems, performance bottlenecks
* **Performance Optimizations:** Query processing, connection handling, memory management
* **Security:** Vulnerability fixes, input validation, secure defaults

### 📖 Documentation
* **README Updates:** Setup instructions, feature explanations, troubleshooting
* **Setup Guides:** Docker deployment, bare metal installation, configuration examples
* **Tutorials:** DNS policy creation, monitoring setup, integration guides
* **Diagrams:** Architecture overviews, data flow, network topology

### 🧪 Testing
* **Unit Tests:** Go function testing, policy engine validation
* **Integration Tests:** End-to-end DNS resolution, policy enforcement
* **Performance Tests:** Load testing, benchmark improvements
* **Fuzz Testing:** Input validation, edge case handling

### 🎨 Design/UX
* **User Interface:** Configuration interfaces, monitoring dashboards
* **Documentation Design:** Clear diagrams, workflow illustrations
* **User Experience:** Installation process, configuration simplicity

---

## 🏗️ Development Setup

### Prerequisites
- **Go 1.21+** for core development
- **Docker & Docker Compose** for containerized development
- **SQLite3** for database operations
- **Git** for version control

### Local Development
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/phantomcore.git
cd phantomcore

# Install dependencies
go mod download

# Build the project
make build

# Run tests
make test

# Start development environment
docker-compose up -d
```

### Code Style Guidelines
* **Go Standards:** Follow effective Go practices and formatting (`gofmt`, `golint`)
* **Error Handling:** Proper error wrapping and context
* **Documentation:** Comment exported functions and complex logic
* **Testing:** Include tests for new features and bug fixes

---

## 🔍 Review Workflow

1. **Initial Review:** Maintainers review PRs for clarity, correctness, and alignment with project standards
2. **Code Quality Checks:** Automated tests, linting, and security scans must pass
3. **Requested Changes:** Address feedback promptly with clear commit messages
4. **Final Approval:** PRs are merged once they meet quality and maintainability requirements
5. **Post-Merge:** Monitor for any issues and be available for quick fixes if needed

---

## � Issue Reporting

When reporting bugs or requesting features:

### 🐛 Bug Reports
* **Clear Title:** Descriptive summary of the issue
* **Environment:** OS, Go version, deployment method (Docker/binary)
* **Steps to Reproduce:** Clear, numbered steps
* **Expected vs Actual:** What should happen vs what actually happens
* **Logs:** Include relevant error messages and log output

### 💡 Feature Requests
* **Use Case:** Explain why this feature would be valuable
* **Proposed Solution:** High-level implementation approach
* **Alternatives:** Other solutions you've considered
* **Breaking Changes:** Note any potential compatibility issues

---

## 📊 Project Structure

Understanding the codebase helps with contributions:

```
phantomcore/
├── cmd/                    # Application entry points
│   ├── controlplane/      # Control plane service
│   └── dataplane/         # Data plane service
├── internal/              # Internal packages
│   ├── dnsengine/         # Core DNS processing
│   ├── policy/            # Policy engine
│   ├── storage/           # Database layer
│   └── config/            # Configuration management
├── configs/               # Configuration files
├── docker/                # Docker configurations
└── docs/                  # Additional documentation
```

---

## 🏆 Recognition

Contributors are recognized through:
* **GitHub Contributors Graph:** Automatic recognition for merged PRs
* **Release Notes:** Major contributors mentioned in release announcements
* **Hall of Fame:** Outstanding contributors featured in project documentation

---

## 📬 Contact & Support

* **GitHub Issues:** For bugs, features, and general discussion
* **LinkedIn:** Reach out to the maintainer via [LinkedIn](https://www.linkedin.com/in/roshan-singh568/)
* **Email:** For security-related issues (prefer GitHub issues for general topics)

---

## 📜 License

By contributing to PhantomCore, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

**We look forward to your contributions and collaboration!** 💡🚀

Together, we're building a more secure and private internet experience through advanced DNS filtering and privacy protection.
