"""Wave 1 smoke test: corsair.cors package is importable."""


def test_cors_package_imports():
    from corsair.cors import CORSAuditor

    assert CORSAuditor is not None


def test_cors_findings_module_imports():
    from corsair.cors import findings

    assert hasattr(findings, "ALL_CORS_FINDINGS")


def test_cors_submodules_exist():
    from corsair.cors import analyzers, auditor, passive, probe

    assert analyzers is not None
    assert auditor is not None
    assert passive is not None
    assert probe is not None
