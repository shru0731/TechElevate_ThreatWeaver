#!/usr/bin/env python3
"""Manual RBAC smoke-check script for a running local server."""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_register():
    """Test user registration."""
    print("1. Testing user registration...")
    # Use a unique email to avoid conflicts
    import time
    timestamp = int(time.time())
    payload = {
        "username": f"testuser{timestamp}",
        "email": f"test{timestamp}@example.com",
        "password": "Test123"
    }
    resp = requests.post(f"{BASE_URL}/auth/register", json=payload)
    print(f"   Register: {resp.status_code}")
    if resp.status_code == 201:
        data = resp.json()
        print(f"   User created: {data['username']} ({data['role']})")
        return data, payload
    else:
        print(f"   Error: {resp.text}")
        return None, None

def test_login(payload):
    """Test user login."""
    print("\n2. Testing user login...")
    login_payload = {
        "email": payload["email"],
        "password": payload["password"]
    }
    resp = requests.post(f"{BASE_URL}/auth/login", json=login_payload)
    print(f"   Login: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        token = data['access_token']
        print(f"   Token received: {token[:20]}...")
        return token
    else:
        print(f"   Error: {resp.text}")
        return None

def test_protected_analysis(token):
    """Test protected analysis endpoint."""
    print("\n3. Testing protected analysis endpoint...")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"entry_node": "A"}
    resp = requests.post(f"{BASE_URL}/analysis/predict", json=payload, headers=headers)
    print(f"   Analysis: {resp.status_code}")
    if resp.status_code == 200:
        print("   ✓ Analyst can access analysis")
    else:
        print(f"   ✗ Error: {resp.text}")

def test_admin_denied(token):
    """Test analyst is denied admin access."""
    print("\n4. Testing analyst denied admin access...")
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/auth/users", headers=headers)
    print(f"   List users: {resp.status_code}")
    if resp.status_code == 403:
        print("   ✓ Analyst correctly denied admin access")
    elif resp.status_code == 200:
        print("   ✗ Analyst should not access admin endpoint")
    else:
        print(f"   ✗ Unexpected error: {resp.text}")

def test_admin_login():
    """Test admin login."""
    print("\n5. Testing admin login...")
    payload = {
        "email": "admin@example.com",
        "password": "Admin123"
    }
    resp = requests.post(f"{BASE_URL}/auth/login", json=payload)
    print(f"   Admin Login: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        token = data['access_token']
        print(f"   Admin token received: {token[:20]}...")
        return token
    else:
        print(f"   Error: {resp.text}")
        return None

def test_admin_can_list_users(admin_token):
    """Test admin can list users."""
    print("\n6. Testing admin can list users...")
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = requests.get(f"{BASE_URL}/auth/users", headers=headers)
    print(f"   List users: {resp.status_code}")
    if resp.status_code == 200:
        users = resp.json()
        print(f"   ✓ Admin can list {len(users)} users")
    else:
        print(f"   ✗ Error: {resp.text}")

def test_admin_can_create_user(admin_token):
    """Test admin can create users."""
    print("\n7. Testing admin can create users...")
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "username": "newanalyst",
        "email": "analyst@example.com",
        "password": "Analyst123",
        "role": "analyst"
    }
    resp = requests.post(f"{BASE_URL}/auth/users", json=payload, headers=headers)
    print(f"   Create user: {resp.status_code}")
    if resp.status_code == 201:
        print("   ✓ Admin can create users")
    else:
        print(f"   ✗ Error: {resp.text}")

def main():
    """Run all tests."""
    print("=== RBAC Manual Testing ===\n")

    # Register user
    user, payload = test_register()
    if not user or not payload:
        return

    # Login
    token = test_login(payload)
    if not token:
        return

    # Test protected endpoints
    test_protected_analysis(token)
    test_admin_denied(token)

    # Test admin functionality
    admin_token = test_admin_login()
    if admin_token:
        test_admin_can_list_users(admin_token)
        test_admin_can_create_user(admin_token)

    print("\n=== Testing Complete ===")

if __name__ == "__main__":
    main()
