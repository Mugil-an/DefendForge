import pytest
from mtd.held_out_techniques import get_held_out_techniques
from mtd.controller import MTDController
from mtd.evaluator import MTDEvaluator


class TestMovingTargetDefense:
    def test_held_out_techniques_catalog(self):
        techniques = get_held_out_techniques()
        assert len(techniques) >= 6
        ids = [t.id for t in techniques]
        assert "xxe_injection" in ids
        assert "ssti_template_injection" in ids
        assert "http_request_smuggling" in ids
        assert "ldap_injection" in ids

    def test_controller_reconfigurations(self):
        controller = MTDController(is_enabled=False)
        assert controller.is_enabled is False

        # Static baseline evaluation
        res = controller.evaluate_request_access("/login")
        assert res["status"] == "normal"
        assert res["is_decoy"] is False

        # Enable MTD
        controller.enable()
        assert controller.is_enabled is True
        assert len(controller.active_route_aliases) > 0
        assert len(controller.decoy_routes) > 0

        # An attacker targeting the static endpoint now gets intercepted by decoy
        res2 = controller.evaluate_request_access("/login")
        assert res2["is_decoy"] is True
        assert res2["status"] == "decoy_intercepted"

    def test_paired_comparison_evaluation(self):
        evaluator = MTDEvaluator()
        report = evaluator.run_paired_comparison()

        assert "static_baseline" in report
        assert "mtd_enabled" in report
        assert "comparison_metrics" in report

        # Static baseline should have higher success rate than MTD
        baseline_rate = report["static_baseline"]["attacker_success_rate"]
        mtd_rate = report["mtd_enabled"]["attacker_success_rate"]

        assert baseline_rate > mtd_rate
        assert report["comparison_metrics"]["success_criterion_met"] is True
        assert report["comparison_metrics"]["attacker_success_reduction_pct"] > 0
