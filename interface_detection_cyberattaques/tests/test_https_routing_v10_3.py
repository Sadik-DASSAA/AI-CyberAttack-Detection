from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


def test_compose_expose_uniquement_https() -> None:
    compose = (PROJECT_DIR / "compose.yaml").read_text(encoding="utf-8")

    assert '"127.0.0.1:443:8443"' in compose
    assert '"127.0.0.1:8000:8000"' not in compose
    assert '"127.0.0.1:8501:8501"' not in compose
    assert "--server.baseUrlPath=SCA" in compose
    assert "caddy:2.11.2" in compose


def test_gateway_conserve_la_capacite_exigee_par_le_binaire_caddy() -> None:
    compose = (PROJECT_DIR / "compose.yaml").read_text(encoding="utf-8")
    gateway = compose.split("\n  gateway:\n", 1)[1].split(
        "\n  data-export:\n", 1
    )[0]

    assert "cap_drop:\n      - ALL" in gateway
    assert "cap_add:\n      - NET_BIND_SERVICE" in gateway
    assert '"127.0.0.1:443:8443"' in gateway
    assert 'user: "10001:10001"' in gateway
    assert "read_only: true" in gateway
    assert "no-new-privileges:true" in gateway


def test_gateway_init_peut_reparer_une_pki_deja_existante() -> None:
    compose = (PROJECT_DIR / "compose.yaml").read_text(encoding="utf-8")
    gateway_init = compose.split("\n  gateway-init:\n", 1)[1].split(
        "\n  gateway:\n", 1
    )[0]

    assert "cap_add:\n      - CHOWN" in gateway_init
    assert "- DAC_OVERRIDE" in gateway_init
    assert "- FOWNER" in gateway_init
    assert "- chown -R 10001:10001 /data /config" in gateway_init
    assert "network_mode: none" in gateway_init


def test_caddy_force_le_chemin_sca_et_les_entetes() -> None:
    caddyfile = (PROJECT_DIR / "Caddyfile").read_text(encoding="utf-8")

    assert "https://localhost:8443" in caddyfile
    assert "local_certs" in caddyfile
    assert "skip_install_trust" in caddyfile
    assert "tls internal" not in caddyfile
    assert "redir @root /SCA/ 308" in caddyfile
    assert "handle /SCA/*" in caddyfile
    assert "Strict-Transport-Security" in caddyfile
    assert "reverse_proxy dashboard:8501" in caddyfile


def test_lanceur_ouvre_uniquement_url_https_propre() -> None:
    launcher = (PROJECT_DIR / "demarrer_tout.ps1").read_text(encoding="utf-8")

    assert '$DashboardUrl = "https://localhost/SCA/"' in launcher
    assert "?version=" not in launcher
    assert '"http://localhost:8501' not in launcher
    assert '"http://localhost:8000/' not in launcher
    assert "Install-SCALocalCertificate" in launcher
    assert "Invoke-DockerCopy" in launcher
    assert '"Cert:\\CurrentUser\\Root"' in launcher
    assert '"Cert:\\LocalMachine\\Root"' in launcher
    assert "Test-SCAHttpsEndpoint" in launcher
    assert "--cacert $CertificatePath" in launcher
    assert "--ssl-revoke-best-effort" in launcher
    assert "\n        --insecure `" not in launcher
    assert "Invoke-WebRequest" not in launcher
    assert '$RunningServices -notcontains "gateway"' in launcher
    assert 'gateway-init gateway' in launcher


def test_lanceur_prepare_le_fichier_threshold_suricata() -> None:
    launcher = (PROJECT_DIR / "demarrer_tout.ps1").read_text(encoding="utf-8")

    assert '$SuricataThresholdConfig = Join-Path $SuricataDirectory "threshold.config"' in launcher
    assert "New-Item `" in launcher
    assert "-Path $SuricataThresholdConfig `" in launcher


def test_bouton_et_route_de_remise_a_zero_sont_presents() -> None:
    app_source = (PROJECT_DIR / "app.py").read_text(encoding="utf-8")
    api_source = (PROJECT_DIR / "api.py").read_text(encoding="utf-8")

    assert '"Réinitialiser le volume"' in app_source
    assert '@st.dialog("Réinitialiser le volume de trafic")' in app_source
    assert 'f"{API_URL}/metrics/traffic/reset"' in app_source
    assert '@app.post("/metrics/traffic/reset")' in api_source
    assert 'record_security_event(' in api_source


if __name__ == "__main__":
    test_compose_expose_uniquement_https()
    test_gateway_conserve_la_capacite_exigee_par_le_binaire_caddy()
    test_gateway_init_peut_reparer_une_pki_deja_existante()
    test_caddy_force_le_chemin_sca_et_les_entetes()
    test_lanceur_ouvre_uniquement_url_https_propre()
    test_lanceur_prepare_le_fichier_threshold_suricata()
    test_bouton_et_route_de_remise_a_zero_sont_presents()
    print("HTTPS ROUTING TESTS PASSED")
