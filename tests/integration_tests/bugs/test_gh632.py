"""Integration test for gh-632.

Verify that if cloud-init is using DataSourceRbxCloud, there is
no traceback if the metadata disk cannot be found.
"""

import pytest

from tests.integration_tests.instances import IntegrationInstance


@pytest.mark.sru_2020_11
def test_datasource_rbx_no_stacktrace(client: IntegrationInstance):
    client.write_to_file(
        '/etc/cloud/cloud.cfg.d/90_dpkg.cfg',
        'datasource_list: [ RbxCloud, NoCloud ]\n',
    )
    client.write_to_file(
        '/etc/cloud/ds-identify.cfg',
        'policy: enabled\n',
    )
    client.execute('cloud-init clean --logs')
    client.restart()

    log = client.read_from_file('/var/log/cloud-init.log')
    assert 'WARNING' not in log
    assert 'Traceback' not in log
    assert 'Failed to load metadata and userdata' not in log
    assert ("Getting data from <class 'cloudinit.sources.DataSourceRbxCloud."
            "DataSourceRbxCloud'> failed") not in log
