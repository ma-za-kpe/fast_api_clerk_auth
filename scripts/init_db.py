#!/usr/bin/env python3
"""
Database initialization script
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from app.db.database import engine, Base
from app.db.models import *
import structlog

logger = structlog.get_logger()


async def init_database():
    """Initialize database with all tables"""
    try:
        logger.info("Starting database initialization...")
        
        async with engine.begin() as conn:
            # Drop all tables (be careful in production!)
            # await conn.run_sync(Base.metadata.drop_all)
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(init_database())