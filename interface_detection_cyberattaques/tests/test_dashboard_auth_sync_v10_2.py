import ast
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def load_dashboard_api_functions():
    source = APP_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = {"auth_headers", "get_api", "get_api_batch"}
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in wanted
    ]
    module = ast.Module(body=functions, type_ignores=[])

    class MainThreadOnlyStreamlit:
        def __init__(self):
            self.main_thread_id = threading.get_ident()
            self._session_state = {"auth_token": "jeton-test-v10-2"}

        @property
        def session_state(self):
            if threading.get_ident() != self.main_thread_id:
                raise RuntimeError("session_state consulté hors du thread principal")
            return self._session_state

    calls = []

    class FakeResponse:
        status_code = 200

    class FakeRequestException(Exception):
        pass

    class FakeRequests:
        Response = FakeResponse
        RequestException = FakeRequestException

        @staticmethod
        def get(url, headers, timeout):
            calls.append({"url": url, "headers": dict(headers), "timeout": timeout})
            return FakeResponse()

    namespace = {
        "st": MainThreadOnlyStreamlit(),
        "requests": FakeRequests,
        "API_URL": "http://api:8000",
        "API_TIMEOUT": (3.0, 15.0),
        "ThreadPoolExecutor": ThreadPoolExecutor,
        "as_completed": as_completed,
    }
    exec(compile(module, APP_PATH, "exec"), namespace)
    return namespace, calls, source


def test_batch_transmet_le_jeton_aux_quatre_requetes():
    namespace, calls, _ = load_dashboard_api_functions()
    responses, errors = namespace["get_api_batch"](
        {
            "statistiques": "/stats",
            "historique": "/history",
            "notifications": "/notifications",
            "modele": "/model-status",
        }
    )

    assert not errors
    assert set(responses) == {
        "statistiques",
        "historique",
        "notifications",
        "modele",
    }
    assert len(calls) == 4
    assert all(
        call["headers"] == {"Authorization": "Bearer jeton-test-v10-2"}
        for call in calls
    )


def test_diagnostic_de_synchronisation_absent_de_l_interface():
    _, _, source = load_dashboard_api_functions()
    assert 'st.expander("Diagnostic de synchronisation")' not in source
