"""Wave 1 smoke test: corsair.cors package is importable."""


def test_cors_package_imports():
    from corsair.cors import CORSAuditor

    assert CORSAuditor is not None


def test_cors_findings_module_imports():
    from corsair.cors import findings

    assert hasattr(findings, "ALL_CORS_FINDINGS")


def test_cors_submodules_exist():
    from corsair.cors import analyzers, auditor, passive, probe

    # The imports themselves are the load-bearing check; these assertions
    # verify each submodule exposes the expected shape.
    assert hasattr(passive, "__doc__")
    assert hasattr(probe, "__doc__")
    assert hasattr(analyzers, "__doc__")
    assert hasattr(auditor, "CORSAuditor")
