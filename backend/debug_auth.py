#!/usr/bin/env python3
"""Debug authentication issues."""
import asyncio
import sys
import os

# Add the backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings
from app.core.security import verify_password, hash_password
from app.models.database import async_session, engine
from sqlalchemy import select, text


async def main():
    print("=" * 60)
    print("Authentication Debug")
    print("=" * 60)

    # Show database location
    print(f"\nDatabase URL: {settings.DATABASE_URL}")
    print(f"Working directory: {os.getcwd()}")

    # Find actual db files
    import glob
    db_files = glob.glob("**/*.db", recursive=True)
    print(f"\nDatabase files found: {db_files}")

    # Test password hashing
    print("\n--- Password Hashing Test ---")
    test_password = "changeme123"
    hashed = hash_password(test_password)
    print(f"Test password: {test_password}")
    print(f"Hash: {hashed}")

    verify_result = verify_password(test_password, hashed)
    print(f"Verify result: {verify_result}")

    # Check database admin user
    print("\n--- Database Admin User ---")
    try:
        async with async_session() as session:
            # Check if table exists and has data
            result = await session.execute(text("SELECT COUNT(*) FROM users"))
            count = result.scalar()
            print(f"Total users in DB: {count}")

            # Get admin user
            result = await session.execute(
                text("SELECT id, username, password_hash, is_active FROM users WHERE username = 'admin'")
            )
            row = result.fetchone()

            if row:
                print(f"Admin user found: id={row[0]}, username={row[1]}, is_active={row[3]}")
                print(f"Stored hash: {row[2]}")

                # Test verification against stored hash
                stored_hash = row[2]
                print(f"\n--- Verify Against Stored Hash ---")
                verify_stored = verify_password(test_password, stored_hash)
                print(f"Verify 'changeme123' against stored hash: {verify_stored}")

                # Also try expected default password from settings
                verify_default = verify_password(settings.DEFAULT_ADMIN_PASSWORD, stored_hash)
                print(f"Verify '{settings.DEFAULT_ADMIN_PASSWORD}' against stored hash: {verify_default}")
            else:
                print("Admin user NOT FOUND!")

    except Exception as e:
        print(f"Database error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
