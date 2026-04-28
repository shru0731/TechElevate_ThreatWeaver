#!/usr/bin/env python3
"""Script to create an admin user in the database."""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from app.database import SessionLocal
from app.models import User
from app.security import hash_password

def create_admin():
    """Create an admin user."""
    db = SessionLocal()
    try:
        # Check if admin already exists
        existing = db.query(User).filter(User.email == "admin@example.com").first()
        if existing:
            print("Admin user already exists")
            return

        # Create admin user
        hashed = hash_password("Admin123")
        admin = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hashed,
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print("Admin user created successfully")
        print("Email: admin@example.com")
        print("Password: Admin123")

    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()