# ============================================================
# Tuskira -> Send Alert (Custom Action)
# Integration parameters consumed:
# - webhook_url : full URL, e.g. https://<your-alert-host>/api/v2/alerts
# - tuskira_api_key : Bearer token (masked)
# ============================================================

import base64
import json
import uuid
from datetime import datetime, timezone

import requests
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Tuskira"
SCRIPT_NAME = "Send Alert"
REQUEST_TIMEOUT = 30  # seconds


def _to_json_safe(v):
    """Recursively convert Siemplify SDK objects to JSON-safe primitives."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v

    if isinstance(v, dict):
        return {k: _to_json_safe(val) for k, val in v.items()}

    if isinstance(v, (list, tuple, set)):
        return [_to_json_safe(x) for x in v]

    if hasattr(v, "__dict__"):
        return {
            k: _to_json_safe(val)
            for k, val in vars(v).items()
            if not k.startswith("_")
        }

    return str(v)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Send Alert START -----------------")

    # 1. Pull integration parameters
    webhook_url = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="webhook_url",
        is_mandatory=True,
        print_value=True,
    )

    api_key = siemplify.extract_configuration_param(
        provider_name=INTEGRATION_NAME,
        param_name="tuskira_api_key",
        is_mandatory=True,
        print_value=False,
    )

    target_url = webhook_url.strip()

    # 2. Build the Chronicle alert envelope
    try:
        alert = siemplify.current_alert
        case = siemplify.case

        chronicle_payload = {
            "case_id": case.identifier if case else None,
            "alert_id": alert.identifier,
            "alert_name": alert.name,
            "rule_generator": getattr(alert, "rule_generator", None),
            "priority": getattr(alert, "priority", None),
            "source_system": getattr(
                alert, "source_system_name", "chronicle"
            ),
            "external_id": getattr(alert, "external_id", None),
            "detection_time": getattr(alert, "creation_time", None),
            "additional_properties": _to_json_safe(
                getattr(alert, "additional_properties", {})
            ),
            "events": [
                _to_json_safe(e)
                for e in getattr(alert, "security_events", [])
            ],
        }

        # DEBUG: Chronicle payload pre-base64
        siemplify.LOGGER.info(
            "Chronicle payload (pre-base64):\n{}".format(
                json.dumps(
                    chronicle_payload,
                    default=str,
                    indent=2,
                )
            )
        )

        data_b64 = base64.b64encode(
            json.dumps(
                chronicle_payload,
                default=str
            ).encode("utf-8")
        ).decode("ascii")

        payload = {
            "run_id": str(uuid.uuid4()),
            "stream_id": "chronicle-secops",
            "batch_sequence_num": 1,
            "events": [
                {
                    "alert_type": "chronicle_alert",
                    "source": "chronicle-secops",
                    "scanned_at": datetime.now(
                        timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "data": data_b64,
                }
            ],
        }

        # DEBUG: full envelope going to Tuskira
        siemplify.LOGGER.info(
            f"Tuskira envelope:\n{json.dumps(payload, indent=2)}"
        )

        siemplify.result.add_result_json(
            {
                "tuskira_envelope_sent": payload,
                "chronicle_payload_decoded": chronicle_payload,
            }
        )

    except Exception as build_err:
        siemplify.LOGGER.error(
            f"Failed to build Tuskira payload: {build_err}"
        )
        siemplify.LOGGER.exception(build_err)

        siemplify.end(
            f"Failed to build Tuskira payload: {build_err}",
            "false",
            EXECUTION_STATE_FAILED,
        )
        return

    # 3. POST to Tuskira
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    siemplify.LOGGER.info(
        f"POST {target_url} "
        f"(events: {len(payload['events'])}, "
        f"run_id: {payload['run_id']})"
    )

    try:
        resp = requests.post(
            target_url,
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )

    except requests.RequestException as net_err:
        siemplify.LOGGER.error(
            f"Network error sending alert to Tuskira: {net_err}"
        )

        siemplify.end(
            f"Network error contacting Tuskira: {net_err}",
            "false",
            EXECUTION_STATE_FAILED,
        )
        return

    # 4. Map response -> SOAR execution state
    status_code = resp.status_code
    body_snippet = (resp.text or "")[:500]

    siemplify.LOGGER.info(
        f"Tuskira response: HTTP {status_code} - body: {body_snippet}"
    )

    if status_code == 200:
        try:
            body = resp.json()

            result_msg = (
                f"Tuskira accepted "
                f"{body.get('processed', '?')} event(s). "
                f"run_id={body.get('run_id')}"
            )

            siemplify.result.add_result_json(
                {
                    "tuskira_response": body,
                    "tuskira_envelope_sent": payload,
                    "chronicle_payload_decoded": chronicle_payload,
                }
            )

        except ValueError:
            result_msg = (
                "Tuskira returned 200 OK (non-JSON body)."
            )

            siemplify.result.add_result_json(
                {
                    "raw": body_snippet,
                    "tuskira_envelope_sent": payload,
                }
            )

        siemplify.end(
            result_msg,
            "true",
            EXECUTION_STATE_COMPLETED,
        )
        return

    if status_code == 207:
        body = resp.json() if resp.text else {}
        errors = body.get("errors", [])

        result_msg = (
            f"Partial success - processed={body.get('processed')} "
            f"failed={body.get('failed')}. "
            f"First error: {errors[0] if errors else 'n/a'}"
        )

        siemplify.result.add_result_json(
            {
                "tuskira_response": body,
                "tuskira_envelope_sent": payload,
                "chronicle_payload_decoded": chronicle_payload,
            }
        )

        siemplify.end(
            result_msg,
            "true",
            EXECUTION_STATE_COMPLETED,
        )
        return

    siemplify.LOGGER.error(
        f"Tuskira responded {status_code}: {body_snippet}"
    )

    siemplify.result.add_result_json(
        {
            "status_code": status_code,
            "response_body": body_snippet,
            "tuskira_envelope_sent": payload,
            "chronicle_payload_decoded": chronicle_payload,
        }
    )

    siemplify.end(
        f"Tuskira returned {status_code}: {body_snippet}",
        "false",
        EXECUTION_STATE_FAILED,
    )


if __name__ == "__main__":
    main()
