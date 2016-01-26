from __future__ import absolute_import
from flask_kerberos_login.manager import KerberosLoginManager

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions


__all__ = ['__version__', 'KerberosLoginManager']
