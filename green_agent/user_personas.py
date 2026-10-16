"""
Green Agent — Realistic Legitimate User Personas and Journeys.

Defines diverse legitimate user behavior models:
  - AnonymousVisitor: browses homepage, about, posts, documentation
  - SearchingCustomer: searches for products, articles, help topics
  - AuthenticatedUser: logs in with valid credentials, views profile, posts comments
  - APIIntegrator: polls health endpoints, queries JSON data
  - InteractiveUser: submits greeting forms, feedback
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

LEGIT_SEARCH_TERMS = [
    "security guide", "getting started", "documentation", "pricing",
    "features", "api reference", "installation", "faq", "changelog",
    "contact support", "account settings", "user manual", "best practices",
]

LEGIT_COMMENTS = [
    "Great article! Thanks for sharing this information.",
    "Very helpful documentation, looking forward to the next update.",
    "Could you provide more examples for the API setup?",
    "Works perfectly in my local development environment.",
    "Appreciate the fast response from the support team.",
]

LEGIT_NAMES = [
    "Alice", "Bob", "Charlie", "Diana", "Evan", "Fiona", "George",
    "Hannah", "Ian", "Julia", "Kevin", "Laura", "Marcus", "Nina",
]


@dataclass
class UserAction:
    """A single HTTP request action by a legitimate user."""
    endpoint: str
    method: str = "GET"
    params: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    description: str = ""


class UserPersona:
    """Base class for legitimate user behavior simulation."""

    def __init__(self, name: str, source_ip: str | None = None):
        self.name = name
        self.source_ip = source_ip or f"192.168.1.{random.randint(2, 250)}"
        self.user_agent = random.choice(USER_AGENTS)

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "X-Forwarded-For": self.source_ip,
        }

    def next_action(self) -> UserAction:
        raise NotImplementedError


class AnonymousVisitor(UserPersona):
    """Browses common static and content pages."""

    PAGES = ["/", "/about", "/posts", "/health", "/robots.txt"]

    def next_action(self) -> UserAction:
        page = random.choice(self.PAGES)
        return UserAction(
            endpoint=page,
            method="GET",
            headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
            description=f"Anonymous visit to {page}",
        )


class SearchingCustomer(UserPersona):
    """Queries legitimate search phrases."""

    def next_action(self) -> UserAction:
        query = random.choice(LEGIT_SEARCH_TERMS)
        return UserAction(
            endpoint="/search",
            method="GET",
            params={"q": query},
            headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
            description=f"Search for '{query}'",
        )


class AuthenticatedUser(UserPersona):
    """Performs legitimate login and authenticated interactions."""

    def __init__(self, username: str = "admin", source_ip: str | None = None):
        super().__init__(username, source_ip)
        self.username = username
        self.is_logged_in = False

    def next_action(self) -> UserAction:
        if not self.is_logged_in:
            self.is_logged_in = True
            return UserAction(
                endpoint="/login",
                method="POST",
                data={"username": self.username, "password": "password"},
                headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
                description=f"Legitimate login attempt by {self.username}",
            )
        else:
            action_choice = random.choice(["comment", "read_post", "greet"])
            if action_choice == "comment":
                return UserAction(
                    endpoint="/comments",
                    method="POST",
                    data={"post_id": 1, "body": random.choice(LEGIT_COMMENTS)},
                    headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
                    description="Submit legitimate comment",
                )
            elif action_choice == "greet":
                name = random.choice(LEGIT_NAMES)
                return UserAction(
                    endpoint="/greet",
                    method="GET",
                    params={"name": name},
                    headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
                    description=f"View greeting for {name}",
                )
            else:
                return UserAction(
                    endpoint="/posts",
                    method="GET",
                    headers={"User-Agent": self.user_agent, "X-Forwarded-For": self.source_ip},
                    description="Browse blog posts",
                )


class APIIntegrator(UserPersona):
    """Automated partner integration querying API endpoints."""

    ENDPOINTS = ["/api", "/api/health", "/status", "/health"]

    def next_action(self) -> UserAction:
        ep = random.choice(self.ENDPOINTS)
        return UserAction(
            endpoint=ep,
            method="GET",
            headers={
                "User-Agent": "PartnerClient/2.4 (ServiceSync)",
                "Accept": "application/json",
                "X-Forwarded-For": self.source_ip,
            },
            description=f"API poll {ep}",
        )


def create_random_persona() -> UserPersona:
    """Create a random legitimate user persona."""
    persona_type = random.choice([AnonymousVisitor, SearchingCustomer, AuthenticatedUser, APIIntegrator])
    if persona_type is AuthenticatedUser:
        return AuthenticatedUser(username="admin")
    return persona_type(name="LegitimateUser")
