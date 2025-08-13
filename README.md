# FastAPI + Clerk Authentication System

A comprehensive, production-ready authentication system built with FastAPI and Clerk, featuring enterprise-grade security, multi-tenancy support, and Docker containerization.

## 🚀 Features

### Core Authentication
- ✅ Email/Password authentication
- ✅ Social OAuth (20+ providers including Google, GitHub, Microsoft)
- ✅ Multi-factor authentication (TOTP, SMS, Email)
- ✅ Passwordless authentication (Magic links, OTP)
- ✅ Session management with JWT tokens
- ✅ Device trust and management

### User Management
- ✅ User registration and profile management
- ✅ Email and phone verification
- ✅ Password reset flows
- ✅ User metadata (public, private, unsafe)
- ✅ Avatar upload support
- ✅ Account deletion with GDPR compliance

### Organization & Teams
- ✅ Multi-tenant organization support
- ✅ Role-based access control (RBAC)
- ✅ Team member management
- ✅ Organization invitations
- ✅ Domain-based auto-join

### Security Features
- ✅ Rate limiting
- ✅ Brute force protection
- ✅ Bot detection
- ✅ Request ID tracking
- ✅ Comprehensive audit logging
- ✅ CORS configuration
- ✅ Security headers

### Enterprise Features
- ✅ SAML SSO support
- ✅ Webhook integration
- ✅ Admin dashboard
- ✅ Prometheus metrics
- ✅ Health checks for Kubernetes

### Developer Experience
- ✅ Docker & Docker Compose setup
- ✅ PostgreSQL database with async support
- ✅ Redis for caching and sessions
- ✅ Structured logging with structlog
- ✅ Comprehensive error handling
- ✅ OpenAPI/Swagger documentation
- ✅ Type hints throughout

## 📋 Prerequisites

- Docker and Docker Compose
- Clerk account (sign up at [clerk.com](https://clerk.com))
- Git

## 🛠️ Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd fast_api_auth
```

### 2. Set Up Environment Variables

Copy the example environment file and configure your Clerk credentials:

```bash
cp .env.example .env
```

Edit `.env` and add your Clerk credentials:
- `CLERK_SECRET_KEY`: Your Clerk secret key
- `CLERK_PUBLISHABLE_KEY`: Your Clerk publishable key
- `CLERK_JWT_VERIFICATION_KEY`: Your JWT verification key (optional)
- `CLERK_WEBHOOK_SECRET`: Your webhook secret (optional)

### 3. Start the Application with Docker

```bash
# Build and start all services
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build
```

The application will be available at:
- API: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- PgAdmin: http://localhost:5050 (admin@example.com / admin)

### 4. Verify Installation

Check the health endpoint:

```bash
curl http://localhost:8000/health
```

## 🏗️ Project Structure

```
fast_api_auth/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── endpoints/      # API endpoints
│   │       ├── deps.py         # Dependencies
│   │       └── router.py       # Main router
│   ├── core/
│   │   ├── config.py          # Configuration
│   │   ├── clerk.py           # Clerk client wrapper
│   │   ├── exceptions.py      # Custom exceptions
│   │   └── logging.py         # Logging setup
│   ├── db/
│   │   └── database.py        # Database configuration
│   ├── middleware/
│   │   ├── authentication.py  # Auth middleware
│   │   ├── rate_limit.py     # Rate limiting
│   │   └── request_id.py     # Request ID tracking
│   ├── schemas/               # Pydantic models
│   └── main.py               # FastAPI application
├── docker-compose.yml        # Docker services
├── Dockerfile               # Container definition
├── pyproject.toml          # Python dependencies
├── .env.example           # Environment template
└── README.md             # This file
```

## 🔐 Authentication Flows

### User Registration

```python
POST /api/v1/auth/signup
{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
}
```

### User Login

```python
POST /api/v1/auth/signin
{
    "email": "user@example.com",
    "password": "SecurePass123!"
}
```

### Protected Endpoints

Include the JWT token in the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8000/api/v1/auth/me
```

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

- **Clerk Settings**: API keys and secrets
- **Database**: PostgreSQL connection string
- **Redis**: Cache and session storage
- **Rate Limiting**: Request limits and time windows
- **Feature Flags**: Enable/disable features
- **Security**: CORS origins, allowed hosts

### Docker Services

The `docker-compose.yml` includes:

- **FastAPI**: Main application server
- **PostgreSQL**: Primary database
- **Redis**: Caching and sessions
- **PgAdmin**: Database management UI

## 📚 API Documentation

### Interactive Documentation

Once running, access the interactive API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Main Endpoints

#### Authentication (`/api/v1/auth`)
- `POST /signup` - User registration
- `POST /signin` - User login
- `POST /signout` - User logout
- `GET /me` - Current user info
- `POST /password-reset` - Request password reset
- `POST /verify-email` - Email verification
- `POST /mfa/setup` - Setup MFA
- `POST /social/{provider}/connect` - Connect social provider

#### Users (`/api/v1/users`)
- `GET /` - List users (admin)
- `GET /{user_id}` - Get user details
- `PATCH /{user_id}` - Update user
- `DELETE /{user_id}` - Delete user
- `GET /{user_id}/sessions` - User sessions

#### Organizations (`/api/v1/organizations`)
- `GET /` - List organizations
- `POST /` - Create organization
- `GET /{org_id}/members` - List members
- `POST /{org_id}/invite` - Invite member

## 🚀 Development

### Local Development without Docker

1. Install Python 3.11+
2. Install Poetry: `pip install poetry`
3. Install dependencies: `poetry install`
4. Run migrations: `alembic upgrade head`
5. Start server: `uvicorn app.main:app --reload`

### Running Tests

```bash
# Run all tests
docker-compose exec fastapi pytest

# Run with coverage
docker-compose exec fastapi pytest --cov=app

# Run specific test file
docker-compose exec fastapi pytest tests/test_auth.py
```

### Code Quality

```bash
# Format code
docker-compose exec fastapi black .

# Sort imports
docker-compose exec fastapi isort .

# Type checking
docker-compose exec fastapi mypy app

# Linting
docker-compose exec fastapi flake8
```

## 🔒 Security Best Practices

1. **Environment Variables**: Never commit `.env` files
2. **Secrets Management**: Use proper secret management in production
3. **HTTPS**: Always use HTTPS in production
4. **Rate Limiting**: Configure appropriate rate limits
5. **CORS**: Restrict origins to trusted domains
6. **Updates**: Keep dependencies updated

## 📊 Monitoring

### Health Checks

- `/health` - Application health status
- `/api/v1/health/status` - Detailed status
- `/api/v1/health/ready` - Readiness probe
- `/api/v1/health/live` - Liveness probe

### Metrics

Prometheus metrics available at `/metrics`

## 🐛 Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 8000, 5432, 6379, 5050 are available
2. **Docker permissions**: Run with appropriate permissions or use sudo
3. **Database connection**: Check DATABASE_URL in .env
4. **Clerk authentication**: Verify API keys are correct

### Logs

View application logs:
```bash
docker-compose logs -f fastapi
```

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues and questions:
- Create an issue in the repository
- Check the [Clerk documentation](https://clerk.com/docs)
- Review FastAPI documentation at [fastapi.tiangolo.com](https://fastapi.tiangolo.com)

## 🎯 Roadmap

- [ ] Add comprehensive test suite
- [ ] Implement all organization features
- [ ] Add email templates
- [ ] Create frontend example
- [ ] Add Kubernetes deployment files
- [ ] Implement advanced RBAC
- [ ] Add data migration tools
- [ ] Create CLI management tool

---

Built with ❤️ using FastAPI and Clerk