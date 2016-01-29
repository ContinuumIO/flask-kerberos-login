'''
Provides a pluggable login manager that uses Kerberos for authentication
'''
from __future__ import absolute_import, print_function, unicode_literals

import base64
import logging
import socket

from flask import _request_ctx_stack as stack
from flask import abort
from flask import request
from flask import Response
from werkzeug.exceptions import HTTPException
import kerberos


log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

def negotiate(token=None):
    '''Generate 'WWW-Authenticate' header value'''
    header = 'Negotiate'
    if token:
        header += ' ' + token

    return header


def _gssapi_authenticate(token, service_name):
    '''
    Performs GSSAPI Negotiate Authentication
    On success also stashes the server response token for mutual authentication
    at the top of request context with the name kerberos_token, along with the
    authenticated user principal with the name kerberos_user.

    Parameters:
        token (str): GSSAPI Authentication Token
        service_name (str): GSSAPI service name

    Returns: (int | None) gssapi return code or None on failure
    '''
    state = None
    ctx = stack.top
    try:
        rc, state = kerberos.authGSSServerInit(service_name)
        if rc != kerberos.AUTH_GSS_COMPLETE:
            log.info('Unable to initialize server context')
            return None
        rc = kerberos.authGSSServerStep(state, token)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            log.debug('Completed GSSAPI negotiation')
            ctx.kerberos_token = kerberos.authGSSServerResponse(state)
            ctx.kerberos_user = kerberos.authGSSServerUserName(state)
            return rc
        elif rc == kerberos.AUTH_GSS_CONTINUE:
            log.debug('Continuing GSSAPI negotiation')
            return kerberos.AUTH_GSS_CONTINUE
        else:
            log.info('Unable to step server context')
            return None
    except kerberos.GSSError:
        log.info('Unable to authenticate', exc_info=True)
        return None
    finally:
        if state:
            kerberos.authGSSServerClean(state)


class KerberosLoginManager(object):

    def __init__(self, app=None):
        self._save_user = None
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
        app.after_request(self.append_header)
        self.init_config(app.config)


    def init_config(self, config):
        service = config.setdefault('KRB5_SERVICE_NAME', b'HTTP')
        hostname = config.setdefault('KRB5_HOSTNAME', socket.gethostname())
        self._service_name = b'{}@{}'.format(service, hostname)

        try:
            principal = kerberos.getServerPrincipalDetails(service, hostname)
        except kerberos.KrbError as exc:
            log.warn("Error initializing Kerberos", exc_info=True)
        else:
            log.info("Server principal is %s", principal)


    def append_header(self, response):
        '''
        Adds WWW-Authenticate header with SPNEGO challenge or Kerberos token
        '''
        kerberos_token = getattr(stack.top, 'kerberos_token', None)
        if response.status_code == 401 or kerberos_token:
            response.headers['WWW-Authenticate'] = negotiate(kerberos_token)

        return response


    def load_user(self, request):
        '''
        Extract a user from the current request

        Raises:

            HTTPException: 401 status if the authentication is incomplete
        '''
        kerberos_user = getattr(stack.top, 'kerberos_user', None)
        if kerberos_user:
            return kerberos_user

        header = request.headers.get(b'authorization')
        if header and header.startswith(b'Negotiate '):

            in_token = header[10:]
            rc = _gssapi_authenticate(in_token, self._service_name)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                user = self._save_user(stack.top.kerberos_user)
                return user
            # else:
            #     abort(403)

            # else:
            #     abort(401)

