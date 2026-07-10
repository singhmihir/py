from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_hello():
    response = client.get("/hello")
    assert response.status_code == 200
    assert response.json() == "Welcome"


def test_hello_name():
    response = client.get("/hello/John")
    assert response.status_code == 200
    assert response.json() == "Welcome John"


def test_get_items_valid_cuisine():
    response = client.get("/get_items/indian")
    assert response.status_code == 200
    assert response.json() == ["Samosa", "Dosa"]


def test_get_items_unknown_cuisine_rejected():
    response = client.get("/get_items/french")
    assert response.status_code == 422


def test_get_coupon():
    response = client.get("/get_coupon/2")
    assert response.status_code == 200
    assert response.json() == {"discount_amount": "20%"}


def test_get_coupon_unknown_code():
    response = client.get("/get_coupon/9")
    assert response.status_code == 200
    assert response.json() == {"discount_amount": None}


def test_get_coupon_non_integer_rejected():
    response = client.get("/get_coupon/abc")
    assert response.status_code == 422
