'''
Provides a pluggable login manager that uses Kerberos for authentication
'''
from __future__ import absolute_import, print_function, unicode_literals

import logging
import socket

from flask import _request_ctx_stack as stack
from flask import abort
from flask import request
import kerberos


log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())


def _gssapi_authenticate(token, service_name):
    '''
    Performs GSSAPI Negotiate Authentication

    Parameters:
        token (str): GSSAPI Authentication Token
        service_name (str): GSSAPI service name

    Returns:
        tuple of
        (str | None) username
        (str | None) GSSAPI token
    '''
    state = None

    try:
        rc, state = kerberos.authGSSServerInit(service_name)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            log.warn('Unable to initialize server context')
            return None, None
        rc = kerberos.authGSSServerStep(state, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            log.debug('Completed GSSAPI negotiation')
            return (
                kerberos.authGSSServerUserName(state),
                kerberos.authGSSServerResponse(state),
            )
        elif rc == kerberos.AUTH_GSS_CONTINUE:
            log.debug('Continuing GSSAPI negotiation')
            return kerberos.AUTH_GSS_CONTINUE
        else:
            log.info('Unable to step server context')
            return None, None
    except kerberos.GSSError:
        log.info('Unable to authenticate', exc_info=True)
        return None, None
    finally:
        if state:
            kerberos.authGSSServerClean(state)


def default_save_callback(user):
    pass


class KerberosLoginManager(object):

    def __init__(self, app=None):
        self._save_user = default_save_callback
        self._service_name = None
        self.app = app

        if app is not None:
            self.init_app(app)

    def save_user(self, callback):
        '''
        This sets the callback for saving a user that has been loaded from a
        kerberos ticket.
        '''
        self._save_user = callback
        return callback


    def init_app(self, app):
        '''
        Initializes the extension with the application object
        '''
        self.app = app
        app.kerberos_manager = self
        app.before_request(self.extract_token)
        app.after_request(self.append_header)
        self.init_config(app.config)


    def init_config(self, config):
        service = config.setdefault('KRB5_SERVICE_NAME', b'HTTP')
        hostname = config.setdefault('KRB5_HOSTNAME', socket.gethostname())
        self._service_name = b'{}@{}'.format(service, hostname)

        try:
            principal = kerberos.getServerPrincipalDetails(service, hostname)
        except kerberos.KrbError:
            log.warn("Error initializing Kerberos for %s", self._service_name, exc_info=True)
        else:
            log.info("Server principal is %s", principal)


    def extract_token(self):
        '''
        Extracts a token from the current HTTP request if it is available.

        Invokes the `save_user` callback if authentication is successful.
        '''
        header = request.headers.get(b'authorization')
        if header and header.startswith(b'Negotiate '):
            token = header[10:]
            user, token = _gssapi_authenticate(token, self._service_name)
            if token is not None:
                stack.top.kerberos_token = token

            if user is not None:
                self._save_user(user)
            else:
                # Invalid Kerberos ticket, we could not complete authentication
                abort(403)


    def append_header(self, response):
        '''
        Adds WWW-Authenticate header with SPNEGO challenge or Kerberos token
        '''
        token = getattr(stack.top, 'kerberos_token', None)
        if response.status_code == 401:
            # Negotiate is an additional authenticate method.
            response.headers.add('WWW-Authenticate', 'Negotiate')
        elif token:
            response.headers['WWW-Authenticate'] = 'Negotiate {}'.format(token)

        return response
