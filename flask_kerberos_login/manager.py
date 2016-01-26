'''
Provides a pluggable login manager that uses Kerberos for authentication
'''
from __future__ import absolute_import, print_function, unicode_literals

import base64
import socket
import logging

from flask import abort
from flask import request
from flask import Response
from flask import _request_ctx_stack as stack
from werkzeug.exceptions import HTTPException

# import gssapi

import kerberos

# log = logging.getLogger(__name__)

log = None

def negotiate(token):
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
    print(token)
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
        global log
        log = app.logger
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
        kerberos_token = getattr(stack.top, 'kerberos_token', None)
        if response.status_code == 401 or kerberos_token:
            response.headers[b'WWW-Authenticate'] = negotiate(kerberos_token)

        return response


    def load_user(self, request):
        header = request.headers.get(b'Authorization')
        if header and header.startswith(b'Negotiate '):
            in_token = base64.b64decode(header[10:])
            in_token = header[10:]

            rc = _gssapi_authenticate(in_token, self._service_name)
            if rc == kerberos.AUTH_GSS_COMPLETE:
                return self._save_user(stack.top.kerberos_user)
            else:
                abort(401)

            # service_name = gssapi.Name(
            #     b'{}@{}'.format(self.config['KRB_SERVICE_NAME'], self.config['KRB_REALM']),
            #     gssapi.C_NT_HOSTBASED_SERVICE,
            # )
            # credential = gssapi.Credential(service_name, usage=gssapi.C_ACCEPT)
            # ctx = gssapi.AcceptContext(credential)

            # out_token = ctx.step(in_token)
            # self.kerberos_token = base64.b64encode(out_token)

            # if ctx.established:
            #     # if self._save_user:
            #     #     self._save_user()
            #     return self._save_user(ctx.peer_name)
            # else:
            #     abort(401)
        else:
            return None



