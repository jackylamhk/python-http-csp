import pytest
from http_csp.csp import CSP


def test_csp_parsing_clean():
    policy = CSP("base-uri self; child-src self http://localhost;")
    assert policy.base_uri == ["self"]
    assert policy.child_src == ["self", "http://localhost"]


def test_csp_parsing_unclean():
    policy = CSP("   base_uri self;child_src  self  http://localhost ;  ")
    assert policy.base_uri == ["self"]
    assert policy.child_src == ["self", "http://localhost"]


def test_csp_parsing_error():
    with pytest.raises(ValueError):
        CSP("non-valid option")


def test_csp_generation():
    policy = CSP()
    policy.base_uri = ["self"]
    policy.child_src = ["self", "http://localhost"]
    generated_policy = policy.generate()
    assert generated_policy == "base-uri self; child-src self http://localhost;"
