import flask
import flask_login
import flask_kerberos_login
import kerberos
import mock
import unittest

class User(flask_login.UserMixin):
    def __init__(self, email):
        self.id = email

class BasicAppTestCase(unittest.TestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.config['TESTING'] = True
        app.config['KRB5_SERVICE_NAME'] = 'HTTP'
        app.config['KRB5_HOSTNAME'] = 'example.org'

        login_manager = flask_login.LoginManager(app)
        manager = flask_kerberos_login.KerberosLoginManager(app)

        @manager.save_user
        def save_user(peer_name):
            user = User(str(peer_name))
            # persist our user to the login manager
            login_manager.reload_user(user)

        @app.route('/')
        @flask_login.login_required
        def index():
            return flask_login.current_user.id

        self.app = app
        self.manager = manager

    def test_unauthorized(self):
        '''
        Ensure that when the client does not send an authorization token, they
        receive a 401 Unauthorized response which includes a www-authenticate
        header field which indicates the server supports Negotiate
        authentication.
        '''
        c = self.app.test_client()
        r = c.get('/')
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers.get('www-authenticate'), 'Negotiate')

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authorized(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an correct authorization token,
        they receive a 200 OK response and the user principal is extracted and
        passed on to the routed method.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.return_value = kerberos.AUTH_GSS_COMPLETE
        name.return_value = "user@EXAMPLE.ORG"
        response.return_value = "STOKEN"
        c = self.app.test_client()
        r = c.get('/', headers={'Authorization': 'Negotiate CTOKEN'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, 'user@EXAMPLE.ORG')
        self.assertEqual(r.headers.get('WWW-Authenticate'), 'Negotiate STOKEN')
        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [mock.call(state)])
        self.assertEqual(response.mock_calls, [mock.call(state)])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_authorized_no_mutual_auth(self, clean, name, response, step, init):
        '''
        Ensure that when a client does not request mutual authentication, we
        don't provide a token & that we don't throw an exception.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.return_value = kerberos.AUTH_GSS_COMPLETE
        name.return_value = "user@EXAMPLE.ORG"
        response.return_value = None
        c = self.app.test_client()
        r = c.get('/', headers={'Authorization': 'Negotiate CTOKEN'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, 'user@EXAMPLE.ORG')
        self.assertEqual(r.headers.get('WWW-Authenticate'), None)
        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [mock.call(state)])
        self.assertEqual(response.mock_calls, [mock.call(state)])
        self.assertEqual(clean.mock_calls, [mock.call(state)])

    @mock.patch('kerberos.authGSSServerInit')
    @mock.patch('kerberos.authGSSServerStep')
    @mock.patch('kerberos.authGSSServerResponse')
    @mock.patch('kerberos.authGSSServerUserName')
    @mock.patch('kerberos.authGSSServerClean')
    def test_forbidden(self, clean, name, response, step, init):
        '''
        Ensure that when the client sends an incorrect authorization token,
        they receive a 403 Forbidden response.
        '''
        state = object()
        init.return_value = (kerberos.AUTH_GSS_COMPLETE, state)
        step.side_effect = kerberos.GSSError("FAILURE")
        c = self.app.test_client()
        r = c.get('/', headers={'Authorization': 'Negotiate CTOKEN'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(init.mock_calls, [mock.call('HTTP@example.org')])
        self.assertEqual(step.mock_calls, [mock.call(state, 'CTOKEN')])
        self.assertEqual(name.mock_calls, [])
        self.assertEqual(response.mock_calls, [])
        self.assertEqual(clean.mock_calls, [mock.call(state)])


if __name__ == '__main__':
    unittest.main()
