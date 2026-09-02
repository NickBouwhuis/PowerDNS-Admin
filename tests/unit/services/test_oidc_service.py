from unittest.mock import patch


def test_oidc_client_uses_pkce():
    settings = {
        "oidc_oauth_enabled": True,
        "oidc_oauth_key": "id",
        "oidc_oauth_secret": "secret",
        "oidc_oauth_api_url": "https://idp.example/api/oidc/",
        "oidc_oauth_scope": "openid profile email",
        "oidc_oauth_auto_configure": True,
        "oidc_oauth_metadata_url": "https://idp.example/.well-known/openid-configuration",
    }
    with patch("powerdnsadmin.services.oidc.Setting") as S, \
            patch("powerdnsadmin.services.oidc.authlib_oauth_client") as client:
        S.return_value.get.side_effect = settings.get
        from powerdnsadmin.services.oidc import oidc_oauth
        oidc_oauth()

    kwargs = client.register.call_args.kwargs
    assert kwargs["client_kwargs"]["code_challenge_method"] == "S256"
    assert kwargs["client_kwargs"]["scope"] == "openid profile email"
    assert kwargs["server_metadata_url"] == settings["oidc_oauth_metadata_url"]
