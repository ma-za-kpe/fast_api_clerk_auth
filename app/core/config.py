from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )
    
    # Clerk Configuration
    CLERK_SECRET_KEY: str = Field(..., description="Clerk secret key")
    CLERK_PUBLISHABLE_KEY: str = Field(..., description="Clerk publishable key")
    CLERK_JWT_VERIFICATION_KEY: Optional[str] = Field(None, description="Clerk JWT verification key")
    CLERK_WEBHOOK_SECRET: Optional[str] = Field(None, description="Clerk webhook secret")
    
    # Database Configuration
    DATABASE_URL: str = Field(
        "postgresql://postgres:postgres@localhost:5432/clerk_auth",
        description="PostgreSQL database URL"
    )
    REDIS_URL: str = Field(
        "redis://localhost:6379",
        description="Redis URL for caching and sessions"
    )
    
    # Application Settings
    ENVIRONMENT: str = Field("development", description="Environment (development, staging, production)")
    DEBUG: bool = Field(True, description="Debug mode")
    SECRET_KEY: str = Field(..., description="Application secret key")
    API_PREFIX: str = Field("/api/v1", description="API prefix")
    
    # CORS Settings
    ALLOWED_ORIGINS: List[str] = Field(
        ["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    ALLOWED_HOSTS: List[str] = Field(["*"], description="Allowed hosts")
    
    # Frontend Configuration
    FRONTEND_URL: str = Field("http://localhost:3000", description="Frontend URL")
    
    # Email Configuration
    SMTP_HOST: Optional[str] = Field(None, description="SMTP server host")
    SMTP_PORT: int = Field(587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(None, description="SMTP password")
    FROM_EMAIL: str = Field("noreply@example.com", description="Default from email")
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = Field(True, description="Enable rate limiting")
    RATE_LIMIT_REQUESTS: int = Field(100, description="Number of requests")
    RATE_LIMIT_PERIOD: int = Field(60, description="Period in seconds")
    
    # Logging
    LOG_LEVEL: str = Field("INFO", description="Logging level")
    LOG_FILE: Optional[str] = Field(None, description="Log file path")
    
    # Session Configuration
    SESSION_LIFETIME: int = Field(86400, description="Session lifetime in seconds")
    REFRESH_TOKEN_LIFETIME: int = Field(604800, description="Refresh token lifetime in seconds")
    
    # Feature Flags
    ENABLE_SOCIAL_AUTH: bool = Field(True, description="Enable social authentication")
    ENABLE_MFA: bool = Field(True, description="Enable multi-factor authentication")
    ENABLE_ORGANIZATIONS: bool = Field(True, description="Enable organizations feature")
    ENABLE_WEBHOOKS: bool = Field(True, description="Enable webhooks")
    ENABLE_ADMIN_PANEL: bool = Field(True, description="Enable admin panel")
    
    # Pagination
    DEFAULT_PAGE_SIZE: int = Field(20, description="Default page size")
    MAX_PAGE_SIZE: int = Field(100, description="Maximum page size")
    
    # File Upload
    MAX_UPLOAD_SIZE: int = Field(10 * 1024 * 1024, description="Maximum upload size in bytes")
    ALLOWED_EXTENSIONS: List[str] = Field(
        [".jpg", ".jpeg", ".png", ".gif", ".pdf"],
        description="Allowed file extensions"
    )
    
    # Password Configuration
    PASSWORD_MIN_LENGTH: int = Field(8, description="Minimum password length")
    PASSWORD_MAX_LENGTH: int = Field(128, description="Maximum password length")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(True, description="Require uppercase letters")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(True, description="Require lowercase letters")
    PASSWORD_REQUIRE_NUMBERS: bool = Field(True, description="Require numbers")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(True, description="Require special characters")
    PASSWORD_CHECK_BREACH: bool = Field(True, description="Check against breach database")
    PASSWORD_MIN_ENTROPY: float = Field(30.0, description="Minimum password entropy")
    PASSWORD_HISTORY_COUNT: int = Field(5, description="Number of previous passwords to check")
    
    # Magic Link Configuration
    MAGIC_LINK_EXPIRY: int = Field(900, description="Magic link expiry in seconds (default 15 min)")
    MAGIC_LINK_STRICT_IP: bool = Field(False, description="Enforce IP address validation")
    MAGIC_LINK_MAX_ATTEMPTS: int = Field(3, description="Max magic link requests per email")
    
    # OTP Configuration
    OTP_LENGTH: int = Field(6, description="Length of OTP code")
    OTP_EXPIRY: int = Field(300, description="OTP expiry in seconds (default 5 min)")
    OTP_MAX_SEND_ATTEMPTS: int = Field(5, description="Max OTP send attempts per identifier")
    OTP_MAX_VERIFY_ATTEMPTS: int = Field(5, description="Max OTP verification attempts")
    OTP_STRICT_IP: bool = Field(False, description="Enforce IP address validation for OTP")
    
    # OAuth Configuration
    GOOGLE_CLIENT_ID: Optional[str] = Field(None, description="Google OAuth client ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(None, description="Google OAuth client secret")
    GITHUB_CLIENT_ID: Optional[str] = Field(None, description="GitHub OAuth client ID")
    GITHUB_CLIENT_SECRET: Optional[str] = Field(None, description="GitHub OAuth client secret")
    MICROSOFT_CLIENT_ID: Optional[str] = Field(None, description="Microsoft OAuth client ID")
    MICROSOFT_CLIENT_SECRET: Optional[str] = Field(None, description="Microsoft OAuth client secret")
    FACEBOOK_CLIENT_ID: Optional[str] = Field(None, description="Facebook OAuth client ID")
    FACEBOOK_CLIENT_SECRET: Optional[str] = Field(None, description="Facebook OAuth client secret")
    DISCORD_CLIENT_ID: Optional[str] = Field(None, description="Discord OAuth client ID")
    DISCORD_CLIENT_SECRET: Optional[str] = Field(None, description="Discord OAuth client secret")
    LINKEDIN_CLIENT_ID: Optional[str] = Field(None, description="LinkedIn OAuth client ID")
    LINKEDIN_CLIENT_SECRET: Optional[str] = Field(None, description="LinkedIn OAuth client secret")
    APPLE_CLIENT_ID: Optional[str] = Field(None, description="Apple OAuth client ID")
    APPLE_CLIENT_SECRET: Optional[str] = Field(None, description="Apple OAuth client secret")
    
    @validator("ALLOWED_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("ALLOWED_HOSTS", pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        if v not in ["development", "staging", "production"]:
            raise ValueError("Environment must be development, staging, or production")
        return v
    
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"
    
    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"


settings = Settings()