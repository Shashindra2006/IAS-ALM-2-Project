
from tls_simulator import TLSSimulator


def test_complete_tls_handshake():
    tls = TLSSimulator()

    step1 = tls.client_hello()
    assert step1["step"] == 1

    step2 = tls.server_hello()
    assert step2["step"] == 2
    assert "PUBLIC KEY" in step2["public_key"]

    step3 = tls.client_key_exchange()
    assert step3["step"] == 3
    assert step3["encrypted_premaster_secret"]

    step4 = tls.generate_session_keys()
    assert step4["client_master_secret_match"] is True
    assert step4["session_keys_match"] is True

    step5 = tls.finished()
    assert step5["secure_channel_established"] is True

    print("All five TLS handshake steps passed!")


if __name__ == "__main__":
    test_complete_tls_handshake()
