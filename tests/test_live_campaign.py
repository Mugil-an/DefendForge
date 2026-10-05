from unittest.mock import Mock, patch

import httpx

from red_agent.live_campaign import LiveCampaign


def test_live_campaign_sends_real_local_http_requests():
    response = Mock(spec=httpx.Response)
    response.status_code = 200
    response.content = b"ok"

    with patch("httpx.Client") as client_type:
        client = client_type.return_value.__enter__.return_value
        client.get.return_value = response
        campaign = LiveCampaign("http://127.0.0.1:5000", max_rounds=1, max_events=1)
        traffic, truth = campaign.run()

    client.get.assert_called_once()
    assert len(traffic) == len(truth) == 1
    assert traffic[0]["destination"] == "127.0.0.1"
    assert truth[0]["is_attack"] is True
