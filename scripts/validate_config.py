#!/usr/bin/env python3
"""
Configuration Validation Script
Validates environment configuration for the FastAPI Clerk Auth application
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dotenv import load_dotenv
import re

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class ConfigValidator:
    """Validates environment configuration"""
    
    def __init__(self, env_file: str = ".env"):
        self.env_file = env_file
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        
        # Load environment variables
        if Path(env_file).exists():
            load_dotenv(env_file)
            self.info.append(f"✓ Loaded environment from {env_file}")
        else:
            self.errors.append(f"✗ Environment file {env_file} not found")
    
    def validate(self) -> bool:
        """Run all validation checks"""
        print("=" * 60)
        print("FastAPI Clerk Auth - Configuration Validator")
        print("=" * 60)
        print()
        
        # Core configuration
        self._validate_core_config()
        
        # Clerk configuration
        self._validate_clerk_config()
        
        # Database configuration
        self._validate_database_config()
        
        # Optional services
        self._validate_optional_services()
        
        # Security settings
        self._validate_security_settings()
        
        # Production checks
        if os.getenv("ENVIRONMENT") == "production":
            self._validate_production_config()
        
        # Display results
        self._display_results()
        
        return len(self.errors) == 0
    
    def _validate_core_config(self):
        """Validate core configuration"""
        print("Checking core configuration...")
        
        # Required core settings
        required = {
            "SECRET_KEY": "Application secret key",
            "ENVIRONMENT": "Environment (development/staging/production)",
            "FRONTEND_URL": "Frontend application URL",
        }
        
        for key, description in required.items():
            value = os.getenv(key)
            if not value:
                self.errors.append(f"✗ {key} is not set ({description})")
            elif key == "SECRET_KEY":
                if value == "your-super-secret-key-change-this-in-production":
                    self.errors.append(f"✗ {key} is using default value - MUST be changed!")
                elif len(value) < 32:
                    self.warnings.append(f"⚠ {key} should be at least 32 characters long")
                else:
                    self.info.append(f"✓ {key} is configured")
            else:
                self.info.append(f"✓ {key} = {value}")
    
    def _validate_clerk_config(self):
        """Validate Clerk configuration"""
        print("Checking Clerk configuration...")
        
        required = {
            "CLERK_SECRET_KEY": "Clerk secret key",
            "CLERK_PUBLISHABLE_KEY": "Clerk publishable key",
        }
        
        for key, description in required.items():
            value = os.getenv(key)
            if not value:
                self.errors.append(f"✗ {key} is not set ({description})")
            elif value.startswith("sk_test_") or value.startswith("pk_test_"):
                if os.getenv("ENVIRONMENT") == "production":
                    self.errors.append(f"✗ {key} is using test key in production!")
                else:
                    self.info.append(f"✓ {key} configured (test mode)")
            elif value.startswith("sk_live_") or value.startswith("pk_live_"):
                if os.getenv("ENVIRONMENT") != "production":
                    self.warnings.append(f"⚠ {key} is using live key in non-production!")
                else:
                    self.info.append(f"✓ {key} configured (live mode)")
            else:
                self.warnings.append(f"⚠ {key} format not recognized")
    
    def _validate_database_config(self):
        """Validate database configuration"""
        print("Checking database configuration...")
        
        # PostgreSQL
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            self.errors.append("✗ DATABASE_URL is not set")
        else:
            # Parse database URL
            if db_url.startswith("postgresql://"):
                self.info.append("✓ PostgreSQL database configured")
                
                # Check for SSL in production
                if os.getenv("ENVIRONMENT") == "production" and "sslmode=" not in db_url:
                    self.warnings.append("⚠ Database SSL not configured for production")
            else:
                self.errors.append("✗ DATABASE_URL must be a PostgreSQL connection string")
        
        # Redis
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            self.errors.append("✗ REDIS_URL is not set")
        else:
            self.info.append("✓ Redis configured")
            
            # Check for password in production
            if os.getenv("ENVIRONMENT") == "production":
                redis_password = os.getenv("REDIS_PASSWORD")
                if not redis_password and ":@" not in redis_url:
                    self.warnings.append("⚠ Redis password not set for production")
    
    def _validate_optional_services(self):
        """Validate optional service configurations"""
        print("Checking optional services...")
        
        # SMS Service
        sms_provider = os.getenv("SMS_PROVIDER")
        if sms_provider == "twilio":
            twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
            twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
            if twilio_sid and twilio_token:
                self.info.append("✓ Twilio SMS service configured")
            else:
                self.warnings.append("⚠ Twilio SMS provider selected but credentials not set")
        
        # Email Service
        smtp_host = os.getenv("SMTP_HOST")
        if smtp_host:
            smtp_user = os.getenv("SMTP_USER")
            smtp_password = os.getenv("SMTP_PASSWORD")
            if smtp_user and smtp_password:
                self.info.append(f"✓ Email service configured ({smtp_host})")
            else:
                self.warnings.append("⚠ SMTP host configured but credentials missing")
        
        # Bot Protection
        if os.getenv("RECAPTCHA_V3_SITE_KEY"):
            self.info.append("✓ reCAPTCHA v3 configured")
        if os.getenv("HCAPTCHA_SITE_KEY"):
            self.info.append("✓ hCaptcha configured")
        if os.getenv("TURNSTILE_SITE_KEY"):
            self.info.append("✓ Cloudflare Turnstile configured")
        
        # Geolocation
        geo_providers = []
        if os.getenv("IPSTACK_KEY"):
            geo_providers.append("IPStack")
        if os.getenv("IPAPI_KEY"):
            geo_providers.append("IP-API")
        if os.getenv("IPGEOLOCATION_KEY"):
            geo_providers.append("IPGeolocation")
        
        if geo_providers:
            self.info.append(f"✓ Geolocation configured: {', '.join(geo_providers)}")
        else:
            self.warnings.append("⚠ No geolocation provider configured")
        
        # OAuth Providers
        oauth_providers = []
        oauth_configs = [
            ("GOOGLE_CLIENT_ID", "Google"),
            ("GITHUB_CLIENT_ID", "GitHub"),
            ("MICROSOFT_CLIENT_ID", "Microsoft"),
            ("FACEBOOK_CLIENT_ID", "Facebook"),
            ("DISCORD_CLIENT_ID", "Discord"),
            ("LINKEDIN_CLIENT_ID", "LinkedIn"),
        ]
        
        for env_key, provider in oauth_configs:
            if os.getenv(env_key):
                oauth_providers.append(provider)
        
        if oauth_providers:
            self.info.append(f"✓ OAuth providers: {', '.join(oauth_providers)}")
    
    def _validate_security_settings(self):
        """Validate security settings"""
        print("Checking security settings...")
        
        # Session settings
        session_lifetime = os.getenv("SESSION_LIFETIME", "86400")
        try:
            lifetime_hours = int(session_lifetime) / 3600
            self.info.append(f"✓ Session lifetime: {lifetime_hours:.1f} hours")
        except ValueError:
            self.errors.append("✗ SESSION_LIFETIME must be a number (seconds)")
        
        # Rate limiting
        if os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true":
            self.info.append("✓ Rate limiting enabled")
        else:
            self.warnings.append("⚠ Rate limiting disabled")
        
        # Password policy
        min_password_length = os.getenv("MIN_PASSWORD_LENGTH", "8")
        try:
            min_length = int(min_password_length)
            if min_length < 8:
                self.warnings.append(f"⚠ Minimum password length ({min_length}) is less than 8")
            else:
                self.info.append(f"✓ Minimum password length: {min_length}")
        except ValueError:
            self.errors.append("✗ MIN_PASSWORD_LENGTH must be a number")
    
    def _validate_production_config(self):
        """Additional validation for production environment"""
        print("Checking production-specific configuration...")
        
        # Debug mode
        if os.getenv("DEBUG", "false").lower() == "true":
            self.errors.append("✗ DEBUG mode is enabled in production!")
        
        # API documentation
        if os.getenv("SHOW_API_DOCS", "true").lower() == "true":
            self.warnings.append("⚠ API documentation is exposed in production")
        
        # HTTPS enforcement
        if os.getenv("FORCE_HTTPS", "false").lower() != "true":
            self.warnings.append("⚠ HTTPS is not enforced in production")
        
        # Backup configuration
        if os.getenv("BACKUP_ENABLED", "false").lower() != "true":
            self.warnings.append("⚠ Backups are not enabled in production")
        
        # Monitoring
        if os.getenv("ENABLE_METRICS", "false").lower() != "true":
            self.warnings.append("⚠ Metrics/monitoring not enabled in production")
    
    def _display_results(self):
        """Display validation results"""
        print()
        print("=" * 60)
        print("VALIDATION RESULTS")
        print("=" * 60)
        print()
        
        # Display info messages
        if self.info:
            print("✅ CONFIGURED:")
            for msg in self.info:
                print(f"  {msg}")
            print()
        
        # Display warnings
        if self.warnings:
            print("⚠️  WARNINGS:")
            for msg in self.warnings:
                print(f"  {msg}")
            print()
        
        # Display errors
        if self.errors:
            print("❌ ERRORS:")
            for msg in self.errors:
                print(f"  {msg}")
            print()
        
        # Summary
        print("=" * 60)
        if self.errors:
            print(f"❌ Validation FAILED with {len(self.errors)} error(s)")
            print("   Please fix the errors above before running the application.")
        elif self.warnings:
            print(f"⚠️  Validation PASSED with {len(self.warnings)} warning(s)")
            print("   The application can run but review the warnings above.")
        else:
            print("✅ Validation PASSED - Configuration looks good!")
        print("=" * 60)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate FastAPI Clerk Auth configuration")
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to environment file (default: .env)"
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Validate as production configuration"
    )
    
    args = parser.parse_args()
    
    # Override environment if production flag is set
    if args.production:
        os.environ["ENVIRONMENT"] = "production"
    
    # Run validation
    validator = ConfigValidator(args.env_file)
    success = validator.validate()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()