# PhantomDNS 🛡️

[![Hac### Prerequisites

- Docker & Docker Compose
- Go 1.20 or higher (for development)
- Git

### Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/lopster568/PhantomDNS.git
    cd PhantomDNS
    ```

2. **Configure the environment** (optional):
    ```sh
    # Copy the example config
    cp configs/config.yaml.example configs/config.yaml
    
    # Edit the configuration file as needed
    vim configs/config.yaml
    ```

3. **Build and run using Docker Compose:**
    ```sh
    docker-compose up --build
    ```

## 🔧 Usage

Once running, PhantomDNS provides two main services:

### Data Plane (DNS Server)
- **Port**: 1053 (UDP and TCP)
- **Purpose**: Handles DNS queries with security filtering
- **Test it**: `dig @localhost -p 1053 example.com`

### Control Plane (Admin API)
- **Port**: 8086
- **Purpose**: Configuration and monitoring interface
- **API Docs**: Visit `http://localhost:8086/docs` for Swagger documentation

### Basic Commands

```sh
# Check DNS server status
curl http://localhost:8086/api/v1/status

# View current blocking rules
curl http://localhost:8086/api/v1/rules

# Add a domain to blocklist
curl -X POST http://localhost:8086/api/v1/rules -d '{"domain": "example.com"}'
```ps://img.shields.io/badge/Hacktoberfest-2025-orange.svg)](https://hacktoberfest.com)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](./LICENSE)
[![Contributors Welcome](https://img.shields.io/badge/contributors-welcome-brightgreen.svg)](./CONTRIBUTING.md)

PhantomDNS is a powerful DNS-layer security & privacy gateway designed to protect your network from threats while maintaining your privacy. Whether you're running it on a Raspberry Pi at home or deploying it in the cloud, PhantomDNS has got you covered.

## ✨ Features

- 🔒 **DNS-layer Security**: Intercepts and filters DNS queries
- 🛡️ **Threat Protection**: Blocks malware, trackers, and unwanted ads
- 📊 **Detailed Reporting**: Monitor your network's security status
- 🎮 **CLI Administration**: Easy-to-use command line interface
- 🐳 **Container Ready**: Deploy anywhere with Docker support
- 🚀 **High Performance**: Optimized for both small devices and cloud deployments

## 🏗️ Architecture

PhantomDNS uses a microservices architecture with two main components:

1. **Data Plane**: The core DNS server handling queries (port 1053)
2. **Control Plane**: Administrative API for configuration (port 8086)

## 🚀 Quick Start

1.  **Clone the repository:**

    ```sh
    git clone https://github.com/lopster568/PhantomDNS.git
    cd PhantomDNS
    ```

2.  **Build and run the services using Docker Compose:**
    ```sh
    docker-compose up --build
    ```

## Usage

The control plane and data plane services will be running in the background.

- **Data Plane (DNS Server):** Listening on port `1053` (UDP and TCP).
- **Control Plane (Admin API):** Listening on port `8086`.

## 🛠️ Development

Want to contribute? Great! We use a standard Go project layout:

```
phantomcore/
├── cmd/                    # Main applications
│   ├── controlplane/      # Admin API service
│   └── dataplane/         # DNS server
├── internal/              # Private application code
│   ├── config/           # Configuration handling
│   ├── core/             # Core DNS logic
│   └── policy/           # Security policy engine
├── configs/               # Configuration files
└── docker/                # Dockerfiles
```

### Building from Source

```sh
# Build the data plane
go build -o bin/dataplane cmd/dataplane/main.go

# Build the control plane
go build -o bin/controlplane cmd/controlplane/main.go
```

### Running Tests

```sh
# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 🤝 Contributing

We welcome contributions! Check out our [Contributing Guidelines](./CONTRIBUTING.md) to get started.

### Good First Issues

Look for issues tagged with `good-first-issue` - these are perfect for newcomers!

### Getting Help

- 📖 Read our [documentation](./docs)
- 💬 Join our [Discord community](https://discord.gg/phantomdns)
- 🐛 Report bugs via [GitHub Issues](https://github.com/lopster568/PhantomDNS/issues)
- 💡 Suggest features in our [Discussions](https://github.com/lopster568/PhantomDNS/discussions)

## 📝 License

PhantomDNS CE is licensed under the GNU General Public License v3.0 (GPLv3).  
See the [LICENSE](./LICENSE) file for details.

## ⭐ Show Your Support

If you find PhantomDNS useful, please consider:

- Giving us a star on GitHub
- Contributing to the project
- Sharing it with others who might benefit

---

Built with ❤️ by the PhantomDNS community
