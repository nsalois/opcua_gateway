"""Host-execute production write ownership across a scripted TLS-read trust change.

TLS, timeout, clock and lock scheduling are explicit doubles. Request generation,
HTTP parsing, runtime ownership and the complete production drain/predicate/result
functions execute unchanged. This is not TLS, target timing or hardware proof.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

def function(source: str, signature: str) -> str:
    """Return one Rust function body, including its signature and braces."""

    start = source.index(signature)
    open_brace = source.index("{", start)
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unclosed Rust function: {signature}")


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "firmware/opta-m7/src/buchi_tls_transport.rs"


class InflightWriteCompletionTests(unittest.TestCase):
    def test_obsolete_trust_reply_has_a_terminal_failed_outcome(self):
        source = SOURCE.read_text()
        parts = []
        for marker in (
            "pub(crate) enum TlsStage", "pub(crate) enum TlsTransportError",
            "pub(crate) trait TlsObserver", "pub(crate) enum BuchiTlsTrustSource",
            "async fn trust_session_current(",
            "async fn drain_pending_writes_over_tls_shared<",
            "async fn record_write_completion_shared(", "fn runtime_trust_revoked(",
            "fn update_cache_status_probe(", "const fn write_stage_for_endpoint(",
        ):
            item = function(source, marker)
            if "enum " in marker:
                item = ("#[derive(Clone, Copy)]\n" if "BuchiTls" in marker else
                        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n") + item
            parts.append(item)
        with tempfile.TemporaryDirectory(prefix="opta-inflight-trust-") as temp:
            work = Path(temp)
            (work / "src").mkdir()
            (work / "src/lib.rs").write_bytes(Path(__file__).with_suffix(".rs").read_bytes())
            (work / "src/firmware.rs").write_text("\n\n".join(parts) + "\n")
            manifest = '[workspace]\n[package]\nname="inflight-trust-host-regression"\nversion="0.1.0"\nedition="2021"\n[dependencies]\n'
            for package, directory in (("opta-runtime", "runtime"), ("opta-buchi", "buchi"),
                                       ("opta-gateway-contracts", "contracts")):
                manifest += f'{package} = {{ path = "{ROOT / "crates" / directory}" }}\n'
            (work / "Cargo.toml").write_text(manifest)
            env = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"))
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=work,
                           env=env, check=True, capture_output=True, text=True, timeout=60)
            for profile in ([], ["--release"]):
                with self.subTest(profile=profile):
                    command = ["cargo", "test", "--locked", "--offline", *profile,
                               "--lib", "--", "--nocapture"]
                    result = subprocess.run(command, cwd=work, env=env, capture_output=True,
                                            text=True, timeout=120)
                    output = result.stdout + result.stderr
                    print(output, end="")
                    self.assertEqual(result.returncode, 0, output)
                    self.assertIn("test result: ok. 4 passed; 0 failed; 0 ignored;", output)
