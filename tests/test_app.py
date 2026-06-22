import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    # We must ensure that missing FIREBASE doesn't crash the tests if not needed
    with app.test_client() as client:
        yield client

def test_homepage(client):
    rv = client.get('/')
    assert rv.status_code == 200

def test_dashboard_get(client):
    rv = client.get('/dashboard')
    assert rv.status_code == 200
