from __future__ import absolute_import

import pytest

from docker_registry_client._BaseClient import BaseClientV1, BaseClientV2
from drc_test_utils.mock_registry import (
    mock_v1_registry, mock_v2_registry,
    TEST_MANIFEST_DIGEST, TEST_NAME, TEST_NAME2, TEST_TAG,
)


class TestBaseClientV1(object):
    def test_check_status(self):
        url = mock_v1_registry()
        BaseClientV1(url).check_status()


class TestBaseClientV2(object):
    def setup_method(self):
        self.url = mock_v2_registry()

    def test_check_status(self):
        BaseClientV2(self.url).check_status()

    def test_get_manifest_and_digest(self):
        manifest, digest = BaseClientV2(self.url).get_manifest_and_digest(TEST_NAME, TEST_TAG)

    def test_deprecation_warnings(self):
        with pytest.warns(DeprecationWarning):
            BaseClientV2(self.url, auth_service_url='https://myhost.com')

    def test_auth_url_defaults(self):
        assert BaseClientV2(self.url, auth_service_url='https://myhost.com').auth.url \
            == 'https://myhost.com/v2/token'

        assert BaseClientV2(self.url, auth_service_url_full='https://myhost.com/foo').auth.url \
            == 'https://myhost.com/foo'

    def test_copy_blob(self):
        BaseClientV2(self.url).copy_blob(TEST_NAME, TEST_MANIFEST_DIGEST, TEST_NAME2)
