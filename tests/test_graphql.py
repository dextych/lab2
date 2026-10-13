from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User


def _register_and_get_token(client: TestClient, email: str) -> str:
    r = client.post("/auth/register", json={
        "email": email,
        "password": "correct-horse-battery",
    })
    return r.json()["access_token"]


def _promote_to_admin(db_session: Session, email: str) -> None:
    user = db_session.query(User).filter(User.email == email).first()
    user.is_admin = True
    db_session.commit()


def test_me_query_without_token(client: TestClient):
    r = client.post("/graphql", json={"query": "query { me { id email } }"})
    body = r.json()
    assert "errors" in body
    assert "Authentication required" in body["errors"][0]["message"]


def test_me_query_with_token(client: TestClient):
    token = _register_and_get_token(client, "gqlme@example.com")

    r = client.post(
        "/graphql",
        json={"query": "query { me { id email isAdmin } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert "errors" not in body
    assert body["data"]["me"]["email"] == "gqlme@example.com"


def test_users_query_without_token(client: TestClient):
    r = client.post("/graphql", json={"query": "query { users { id email } }"})
    body = r.json()
    assert "errors" in body
    assert "Authentication required" in body["errors"][0]["message"]


def test_users_query_as_non_admin_returns_admin_only(client: TestClient):
    token = _register_and_get_token(client, "user@example.com")

    r = client.post(
        "/graphql",
        json={"query": "query { users { id email } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert "errors" in body
    assert "Admin only" in body["errors"][0]["message"]


def test_users_query_as_admin(client: TestClient, db_session: Session):
    email = "admin@example.com"
    token = _register_and_get_token(client, email)
    _promote_to_admin(db_session, email)

    r = client.post(
        "/graphql",
        json={"query": "query { users { id email isAdmin } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert "errors" not in body
    users = body["data"]["users"]
    assert any(u["email"] == email for u in users)


def test_create_client_as_admin(client: TestClient, db_session: Session):
    email = "admin2@example.com"
    token = _register_and_get_token(client, email)
    _promote_to_admin(db_session, email)

    r = client.post(
        "/graphql",
        json={
            "query": """
                mutation {
                    createClient(name: "Demo App", isConfidential: false) {
                        id
                        clientId
                        name
                        isConfidential
                    }
                }
            """,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert "errors" not in body
    client_data = body["data"]["createClient"]
    assert client_data["name"] == "Demo App"
    assert client_data["isConfidential"] is False
    assert len(client_data["clientId"]) == 32  # uuid4().hex


def test_disable_user_as_admin(client: TestClient, db_session: Session):
    admin_email = "admin3@example.com"
    admin_token = _register_and_get_token(client, admin_email)
    _promote_to_admin(db_session, admin_email)

    _register_and_get_token(client, "victim@example.com")
    victim = db_session.query(User).filter(User.email == "victim@example.com").first()

    r = client.post(
        "/graphql",
        json={
            "query": f"""
                mutation {{
                    disableUser(userId: {victim.id}) {{
                        id
                        email
                        isActive
                    }}
                }}
            """,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    body = r.json()
    assert "errors" not in body
    assert body["data"]["disableUser"]["isActive"] is False