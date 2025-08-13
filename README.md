# FastAPI Clerk Auth - Enterprise Authentication System

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![PostgreSQL](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**A production-ready, enterprise-grade authentication and authorization system built with FastAPI and Clerk**

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [API Reference](#api-reference) • [Contributing](#contributing)

</div>

---

## 🚀 Overview

FastAPI Clerk Auth is a comprehensive, **open-source** authentication system that provides enterprise-grade security features, multi-tenancy support, and seamless integration with modern web applications. Built on top of FastAPI and integrated with Clerk authentication, it offers a complete solution for user management, authentication, and authorization.

### Key Highlights

- **🔐 20+ OAuth Providers** - Google, GitHub, Microsoft, Facebook, Discord, LinkedIn, and more
- **🛡️ Advanced Security** - MFA/2FA, WebAuthn/Passkeys, Bot Protection, Geolocation Security
- **🏢 Enterprise Ready** - SAML SSO, RBAC, Custom Roles, Audit Logging
- **👥 Multi-Tenancy** - Organizations, Workspaces, Teams with isolated permissions
- **📊 Complete Observability** - Analytics, Monitoring, Audit Trails
- **✅ Compliance** - GDPR/CCPA compliant with soft delete and data export features
- **⚡ High Performance** - Redis caching, async operations, optimized queries
- **🌍 Open Source** - MIT licensed, community-driven development

## 📋 Features

### Core Authentication
- ✅ **Email/Password** - Traditional authentication with breach detection
- ✅ **Magic Links** - Passwordless email authentication
- ✅ **OAuth/Social Login** - 20+ providers pre-configured
- ✅ **Multi-Factor Authentication** - TOTP, SMS, Email, Backup codes
- ✅ **WebAuthn/Passkeys** - Biometric authentication (Face ID, Touch ID, YubiKey)

### User Management
- ✅ **Profile Management** - Complete user profiles with metadata
- ✅ **Avatar Management** - Image upload and management
- ✅ **Email Verification** - Double opt-in flows
- ✅ **Password Management** - Reset, rotation, strength validation
- ✅ **Account Deletion** - GDPR-compliant soft delete with recovery

### Organization & Teams
- ✅ **Multi-Organization** - Users can belong to multiple organizations
- ✅ **Workspaces/Teams** - Sub-organization workspaces
- ✅ **Invitations** - Email-based invitation system
- ✅ **Domain Verification** - Auto-join via email domain
- ✅ **Member Management** - Add, remove, update roles

### Security Features
- ✅ **Rate Limiting** - Configurable per-endpoint limits
- ✅ **Bot Protection** - reCAPTCHA v3, hCaptcha, custom challenges
- ✅ **Geolocation Security** - Impossible travel detection, country blocking
- ✅ **Email Security** - Disposable email blocking, domain validation
- ✅ **Device Management** - Trusted devices, fingerprinting
- ✅ **Session Management** - Concurrent session limits, remote logout

### Enterprise Features
- ✅ **SAML 2.0 SSO** - Support for Okta, Azure AD, Google Workspace
- ✅ **RBAC** - Role-based access control with custom roles
- ✅ **Custom Permissions** - Granular permission system
- ✅ **Audit Logging** - Comprehensive activity tracking
- ✅ **Webhooks** - Event-driven integrations
- ✅ **API Keys** - Scoped API key management

### Compliance & Privacy
- ✅ **GDPR Compliance** - Right to access, deletion, portability
- ✅ **CCPA Compliance** - California privacy rights
- ✅ **Data Export** - Export user data in JSON/CSV
- ✅ **Consent Management** - Track and manage user consents
- ✅ **Audit Trail** - Complete audit logging

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- PostgreSQL 13+
- Redis 6+
- Clerk Account (get one at [clerk.com](https://clerk.com))

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ma-za-kpe/fast_api_clerk_auth.git
cd fast_api_clerk_auth
```

2. **Set up virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
# or using poetry
poetry install
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Set up the database**
```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run migrations
alembic upgrade head

# Initialize database
python scripts/init_db.py
```

6. **Run the application**
```bash
# Development
uvicorn app.main:app --reload --port 8000

# Production
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up --build

# Or use the production Dockerfile
docker build -t fastapi-clerk-auth .
docker run -p 8000:8000 --env-file .env fastapi-clerk-auth
```

## 📖 Documentation

### Configuration

The application is configured through environment variables. See [.env.example](.env.example) for all available options.

**Key configuration areas:**
- **Clerk**: API keys and webhook secrets
- **Database**: PostgreSQL and Redis connections
- **Security**: Session settings, rate limits, password policies
- **Features**: Enable/disable specific features
- **OAuth**: Configure social login providers
- **Email**: SMTP settings for email delivery
- **SMS**: Twilio configuration for SMS OTP

### Project Structure

```
fast_api_auth/
├── app/
│   ├── api/v1/          # API endpoints
│   ├── core/            # Core configuration and utilities
│   ├── db/              # Database models and connection
│   ├── middleware/      # Custom middleware
│   ├── models/          # SQLAlchemy models
│   ├── schemas/         # Pydantic schemas
│   ├── services/        # Business logic services
│   ├── tasks/           # Background tasks (Celery)
│   └── templates/       # Email templates
├── scripts/             # Utility scripts
├── tests/              # Test suite
├── alembic/            # Database migrations
├── docker-compose.yml  # Docker services
└── pyproject.toml      # Project dependencies
```

### API Documentation

Once running, access the interactive API documentation:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Feature Documentation

See [FEATURE_FLOWS.md](FEATURE_FLOWS.md) for detailed documentation of all features including:
- Flow diagrams
- API endpoints
- Frontend implementation examples
- Testing strategies

## 🔧 API Reference

### Authentication Endpoints

```http
POST   /api/v1/auth/signup              # User registration
POST   /api/v1/auth/login               # User login
POST   /api/v1/auth/logout              # User logout
POST   /api/v1/auth/refresh             # Refresh access token
POST   /api/v1/auth/forgot-password     # Request password reset
POST   /api/v1/auth/reset-password      # Reset password
POST   /api/v1/auth/verify-email        # Verify email address
```

### User Management

```http
GET    /api/v1/users/me                 # Get current user
PUT    /api/v1/users/me                 # Update user profile
DELETE /api/v1/users/me                 # Delete user account
POST   /api/v1/users/me/avatar          # Upload avatar
```

### Multi-Factor Authentication

```http
POST   /api/v1/mfa/enable               # Enable MFA
POST   /api/v1/mfa/setup/totp           # Setup TOTP
POST   /api/v1/mfa/verify/totp          # Verify TOTP code
POST   /api/v1/mfa/setup/sms            # Setup SMS MFA
POST   /api/v1/mfa/backup-codes         # Generate backup codes
```

### OAuth/Social Login

```http
GET    /api/v1/oauth/providers          # List available providers
GET    /api/v1/oauth/{provider}/auth    # Initiate OAuth flow
GET    /api/v1/oauth/{provider}/callback # OAuth callback
POST   /api/v1/oauth/{provider}/link    # Link OAuth account
DELETE /api/v1/oauth/{provider}/unlink  # Unlink OAuth account
```

### Organizations & Teams

```http
POST   /api/v1/organizations            # Create organization
GET    /api/v1/organizations            # List user's organizations
GET    /api/v1/organizations/{id}       # Get organization details
PUT    /api/v1/organizations/{id}       # Update organization
DELETE /api/v1/organizations/{id}       # Delete organization

POST   /api/v1/workspaces               # Create workspace
GET    /api/v1/workspaces               # List workspaces
POST   /api/v1/workspaces/{id}/members  # Add workspace member
```

For complete API documentation, see the [API Reference](https://github.com/ma-za-kpe/fast_api_clerk_auth/wiki/API-Reference).

## 🧪 Testing

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py

# Run with verbose output
pytest -v
```

### Test Categories

- **Unit Tests**: Test individual components
- **Integration Tests**: Test service interactions
- **E2E Tests**: Test complete user flows
- **Security Tests**: Test security features

## 🚢 Deployment

### Production Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Configure production database
- [ ] Set up Redis with password
- [ ] Enable HTTPS/SSL
- [ ] Configure CORS origins
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure backup strategy
- [ ] Set up log aggregation
- [ ] Review security settings
- [ ] Configure rate limits

### Deployment Options

#### Docker
```bash
docker build -t fastapi-clerk-auth .
docker run -d \
  --name fastapi-auth \
  -p 8000:8000 \
  --env-file .env.production \
  fastapi-clerk-auth
```

#### Kubernetes
```yaml
# See k8s/ directory for Kubernetes manifests
kubectl apply -f k8s/
```

#### Cloud Platforms
- **AWS**: Use ECS, EKS, or Elastic Beanstalk
- **Google Cloud**: Use Cloud Run or GKE
- **Azure**: Use Container Instances or AKS
- **Heroku**: Use Procfile with gunicorn

## 🔒 Security

### Security Features

- **Password Security**: Bcrypt hashing, breach detection, strength validation
- **Token Security**: JWT with refresh tokens, automatic rotation
- **Rate Limiting**: Per-endpoint and per-user limits
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **XSS Protection**: Content sanitization and CSP headers
- **CSRF Protection**: State validation for OAuth flows

### Reporting Security Issues

As an open-source project, we take security seriously. Please report security vulnerabilities through GitHub Security Advisories or by creating an issue with the `security` label.

## 📊 Monitoring

### Metrics

The application exposes Prometheus metrics at `/metrics`:
- Request duration
- Request count
- Error rate
- Active sessions
- Authentication attempts

### Health Checks

```http
GET /health          # Basic health check
GET /health/ready    # Readiness check
GET /health/live     # Liveness check
```

## 🤝 Contributing

We welcome contributions! As an open-source project, we encourage the community to help improve and extend the system.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Development Setup

1. Fork the repository
2. Clone your fork
3. Install dependencies: `poetry install`
4. Create a branch for your feature
5. Make your changes
6. Write/update tests
7. Ensure all tests pass
8. Submit a pull request

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings to functions
- Write tests for new features
- Update documentation as needed

### Areas for Contribution

- 🧪 **Testing**: Improve test coverage
- 📚 **Documentation**: Enhance documentation, add tutorials
- 🌍 **Internationalization**: Add language support
- 🔌 **Integrations**: Add new OAuth providers or services
- 🐛 **Bug Fixes**: Help fix reported issues
- ✨ **Features**: Implement new features from the roadmap
- 🎨 **Frontend Examples**: Create example frontend implementations

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

This means you can:
- ✅ Use commercially
- ✅ Modify
- ✅ Distribute
- ✅ Private use

## 🙏 Acknowledgments

This open-source project is built on top of amazing technologies:

- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Clerk](https://clerk.com/) - Authentication infrastructure
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database toolkit
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation
- [Redis](https://redis.io/) - Caching and sessions

## 📞 Support

- **Documentation**: [Wiki](https://github.com/ma-za-kpe/fast_api_clerk_auth/wiki)
- **Issues**: [GitHub Issues](https://github.com/ma-za-kpe/fast_api_clerk_auth/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ma-za-kpe/fast_api_clerk_auth/discussions)
- **Community**: Join our community to discuss features and get help

## 🗺️ Roadmap

We're actively working on:

- [ ] Complete test suite with 90%+ coverage
- [ ] GraphQL API support
- [ ] Real-time notifications (WebSockets)
- [ ] Frontend SDKs (React, Vue, Angular)
- [ ] Mobile SDKs (iOS/Android)
- [ ] Additional OAuth providers
- [ ] Advanced analytics dashboard
- [ ] Machine learning-based fraud detection
- [ ] Kubernetes Helm charts
- [ ] Terraform modules for cloud deployment
- [ ] CLI management tool
- [ ] Admin dashboard UI

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ma-za-kpe/fast_api_clerk_auth&type=Date)](https://star-history.com/#ma-za-kpe/fast_api_clerk_auth&Date)

## 📈 Project Stats

- **Lines of Code**: 47,000+
- **API Endpoints**: 200+
- **OAuth Providers**: 20+
- **Features**: 100+

---

<div align="center">

**Built with ❤️ by the Open Source Community**

⭐ **Star us on GitHub** — it motivates us to keep improving!

🍴 **Fork the project** — make it your own!

🤝 **Contribute** — help us make it better!

[Report Bug](https://github.com/ma-za-kpe/fast_api_clerk_auth/issues) · [Request Feature](https://github.com/ma-za-kpe/fast_api_clerk_auth/issues) · [Join Discussion](https://github.com/ma-za-kpe/fast_api_clerk_auth/discussions)

</div>