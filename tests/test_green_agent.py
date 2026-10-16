import pytest
from green_agent.user_personas import (
    AnonymousVisitor, SearchingCustomer, AuthenticatedUser, APIIntegrator, create_random_persona
)
from green_agent.traffic_generator import GreenTrafficGenerator


class TestGreenAgent:
    def test_user_personas(self):
        visitor = AnonymousVisitor("Anon")
        action = visitor.next_action()
        assert action.method == "GET"
        assert action.endpoint in AnonymousVisitor.PAGES
        assert "User-Agent" in action.headers

        searcher = SearchingCustomer("Searcher")
        action2 = searcher.next_action()
        assert action2.endpoint == "/search"
        assert "q" in action2.params

        user = AuthenticatedUser("admin")
        action3 = user.next_action()
        assert action3.endpoint == "/login"
        assert action3.method == "POST"

        api = APIIntegrator("Partner")
        action4 = api.next_action()
        assert action4.endpoint in APIIntegrator.ENDPOINTS

    def test_random_persona(self):
        p = create_random_persona()
        action = p.next_action()
        assert action.endpoint.startswith("/")

    def test_traffic_generator_batch(self):
        gen = GreenTrafficGenerator(target_url="http://127.0.0.1:8080")
        events = gen.generate_batch(10)
        assert len(events) == 10
        for ev in events:
            assert ev["is_attack"] is False
            assert ev["source_kind"] == "green_agent"
            assert ev["endpoint"].startswith("/")
        assert gen.total_requests == 10

    def test_service_disruption_metrics(self):
        gen = GreenTrafficGenerator(target_url="http://127.0.0.1:8080")
        gen.total_requests = 100
        gen.successful_requests = 98
        gen.blocked_requests = 2
        metrics = gen.get_service_disruption_metrics()
        assert metrics["false_positive_block_rate"] == 0.02
        assert metrics["availability_rate"] == 0.98
        assert metrics["service_disrupted"] is True
