"""
Copyright 2010-2012 cloudControl UG (haftungsbeschraenkt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import time
import calendar
import socket
import httplib2
from urllib import urlencode
from urlparse import urlparse
# python versions below 2.6 do not have json included we need simplejson then
try:
    import json
except ImportError:
    #noinspection PyUnresolvedReferences
    import simplejson as json


from pycclib.version import __version__ as VERSION

__all__ = ['API', 'UnauthorizedError', 'ConnectionException',
           'TokenRequiredError', 'BadRequestError', 'ForbiddenError',
           'ConflictDuplicateError', 'GoneError', 'InternalServerError',
           'NotImplementedError', 'ThrottledError']

API_URL = 'https://api.cloudcontrol.com'
DISABLE_SSL_CHECK = False
CA_CERTS = None
# Set debug to 1 to enable debugging
DEBUG = 0


class API():
    """
        The API class contains all methods to access the cloudControl RESTful
        API.

        It wraps the HTTP requests to resources in convenient methods and also
        takes care of authenticating each request with a token, if needed.

        The create_token, check_token, get_token and set_token methods can be
        used to work with the token from outside the API class. This might be
        useful when it is not intended to ask users for their email and
        password for new instances of the API class.

        To instantiate API with a predefined token use something like:

        # token = json.loads('{"token": "A2wY7qgUNM5eTRM3Lz6D4RZHuGmYPP"}')
        # api = API(token=token)
    """

    _token = None
    url = None

    def __init__(self, token=None):
        self.set_token(token)

    def check_versions(self):
        request = Request()
        content = request.get('/.meta/version/')
        return json.loads(content)

    def requires_token(self):
        if not self.check_token():
            raise TokenRequiredError

    def create_token(self, email, password):
        request = Request(email=email, password=password)
        content = request.post('/token/')
        self.set_token(json.loads(content))
        return True

    def check_token(self):
        token = self.get_token()
        if token:
            return True
        return False

    def set_token(self, token):
        self._token = token

    def get_token(self):
        return self._token

    def create_app(self, app_name, type, repository_type):
        self.requires_token()
        resource = '/app/'
        data = {
                'name': app_name,
                'type': type,
                'repository_type': repository_type}
        request = Request(token=self.get_token())
        content = request.post(resource, data)
        return json.loads(content)

    def read_apps(self):
        self.requires_token()
        resource = '/app/'
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def read_app(self, app_name):
        self.requires_token()
        resource = '/app/%s/' % app_name
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def delete_app(self, app_name):
        self.requires_token()
        resource = '/app/%s/' % app_name
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def create_deployment(self, app_name, deployment_name='', stack=None):
        self.requires_token()
        resource = '/app/%s/deployment/' % app_name
        request = Request(token=self.get_token())
        data = {}
        if deployment_name:
            data['name'] = deployment_name
        if stack:
            data['stack'] = stack
        content = request.post(resource, data)
        return json.loads(content)

    def read_deployment(self, app_name, deployment_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def update_deployment(self,
                          app_name,
                          version=-1,
                          deployment_name='default',
                          min_boxes=None,
                          max_boxes=None,
                          billing_account=None,
                          stack=None):
        """
            Updates a deployment.

            Use this to deploy new versions. If no version is provided the
            last pushed version is deployed.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        data = {'version': version}
        if min_boxes:
            data['min_boxes'] = min_boxes
        if max_boxes:
            data['max_boxes'] = max_boxes
        if billing_account:
            data['billing_account'] = billing_account
        if stack:
            data['stack'] = stack
        content = request.put(resource, data)
        return json.loads(content)

    def delete_deployment(self, app_name, deployment_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def create_alias(self, app_name, alias_name, deployment_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        data = {'name': alias_name}
        content = request.post(resource, data)
        return json.loads(content)

    def read_aliases(self, app_name=None, deployment_name=None):
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/alias/' % \
                (app_name, deployment_name)
            request = Request(token=self.get_token())
            content = request.get(resource)
        return json.loads(content)

    def read_alias(self, app_name, alias_name, deployment_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/%s/' % \
            (app_name, deployment_name, alias_name)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def delete_alias(self, app_name, alias_name, deployment_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/%s/' % \
            (app_name, deployment_name, alias_name)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def create_worker(self, app_name, deployment_name, command, params=None, size=None):
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/' % \
            (app_name, deployment_name)
        request = Request(token=self.get_token())
        data = {'command': command}
        if params:
            data['params'] = params
        if size:
            data['size'] = size
        content = request.post(resource, data)
        return json.loads(content)

    def read_workers(self, app_name=None, deployment_name=None):
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/worker/' % \
                (app_name, deployment_name)
            request = Request(token=self.get_token())
            content = request.get(resource)
        return json.loads(content)

    def read_worker(self, app_name, deployment_name, wrk_id):
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/%s/' % \
            (app_name, deployment_name, wrk_id)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def delete_worker(self, app_name, deployment_name, wrk_id):
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/%s/' % \
            (app_name, deployment_name, wrk_id)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def create_cronjob(self, app_name, deployment_name, url):
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        data = {'url': url}
        content = request.post(resource, data)
        return json.loads(content)

    def read_cronjobs(self, app_name=None, deployment_name=None):
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/cron/' % \
                (app_name, deployment_name)
            request = Request(token=self.get_token())
            content = request.get(resource)
        return json.loads(content)

    def read_cronjob(self, app_name, deployment_name, job_id):
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/%s/' % \
            (app_name, deployment_name, job_id)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def delete_cronjob(self, app_name, deployment_name, job_id):
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/%s/' % \
            (app_name, deployment_name, job_id)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def create_addon(self, app_name, deployment_name, addon_name, options=None):
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/' % (app_name, deployment_name)
        request = Request(token=self.get_token())
        data = {'addon': addon_name}
        if options:
            data['options'] = options
        content = request.post(resource, data)
        return json.loads(content)

    def read_addons(self, app_name=None, deployment_name=None):
        """
            Get a list of addons.

            If app_name or deployment_name are None it will return a list
            of available addons. Otherwise a list of addons related to that
            deployment is returned.
        """
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/addon/' % \
                (app_name, deployment_name)
            request = Request(token=self.get_token())
            content = request.get(resource)
        else:
            resource = '/addon/'
            request = Request(token=self.get_token())
            content = request.get(resource)
        return json.loads(content)

    def read_addon(self, app_name, deployment_name, addon_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def update_addon(self, app_name, deployment_name, addon_name_current, addon_name_to_update_to):
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name_current)
        request = Request(token=self.get_token())
        data = {'addon': addon_name_to_update_to}
        content = request.put(resource, data)
        return json.loads(content)

    def delete_addon(self, app_name, deployment_name, addon_name):
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def read_app_users(self, app_name):
        """Get the list of users associated with the app."""
        self.requires_token()
        resource = '/app/%s/user/' % app_name
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def create_app_user(self, app_name, email):
        """Add a user to an application."""
        self.requires_token()
        resource = '/app/%s/user/' % app_name
        request = Request(token=self.get_token())
        data = {'email': email}
        content = request.post(resource, data)
        return json.loads(content)

    def delete_app_user(self, app_name, user_name):
        """Remove a user from an application."""
        self.requires_token()
        resource = '/app/%s/user/%s/' % (app_name, user_name)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def read_users(self):
        self.requires_token()
        resource = '/user/'
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def create_user(self, name, email, password):
        resource = '/user/'
        request = Request()
        data = {
            'username': name,
            'email': email,
            'password': password}
        content = request.post(resource, data)
        return json.loads(content)

    def read_user(self, user_name):
        self.requires_token()
        resource = '/user/%s/' % user_name
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def update_user(self, user_name, activation_code=None):
        """Activate a user account."""
        resource = '/user/%s/' % user_name
        if activation_code:
            request = Request()
            data = {'activation_code': activation_code}
            request.put(resource, data)
        else:
            # Not implemented yet
            return False
        return True

    def delete_user(self, user_name):
        self.requires_token()
        resource = '/user/%s/' % user_name
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def read_user_keys(self, user_name):
        self.requires_token()
        resource = '/user/%s/key/' % user_name
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def read_user_key(self, user_name, key_id):
        self.requires_token()
        resource = '/user/%s/key/%s/' % (user_name, key_id)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def create_user_key(self, user_name, public_key):
        self.requires_token()
        resource = '/user/%s/key/' % user_name
        request = Request(token=self.get_token())
        data = {'key': public_key}
        content = request.post(resource, data)
        return json.loads(content)

    def delete_user_key(self, user_name, key_id):
        """
            Remove a key from a user.

            Requires key_id that can be requested using read_user_keys()
        """
        self.requires_token()
        resource = '/user/%s/key/%s/' % (user_name, key_id)
        request = Request(token=self.get_token())
        request.delete(resource)
        return True

    def read_log(self, app_name, deployment_name, log_type, last_time=None):
        """
            Return deployment log of specified type.

            Args:
              log_type: 'access', 'error', 'deploy' or 'worker'
              last_time (optional): only return log lines newer than this python time struct
        """
        self.requires_token()
        if last_time:
            timestamp = calendar.timegm(last_time)
            resource = '/app/%s/deployment/%s/log/%s/?timestamp=%s' % \
                (app_name, deployment_name, log_type, timestamp)
        else:
            resource = '/app/%s/deployment/%s/log/%s/' % \
                (app_name, deployment_name, log_type)
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)

    def create_billing_account(self, userName, billingName, data):
        self.requires_token()
        resource = '/user/%s/billing/%s/' % (userName, billingName)
        request = Request(token=self.get_token())
        content = request.post(resource, data)
        return json.loads(content)

    def update_billing_account(self, userName, billingName, data):
        self.requires_token()
        resource = '/user/%s/billing/%s/' % (userName, billingName)
        request = Request(token=self.get_token())
        content = request.put(resource, data)
        return json.loads(content)

    def get_billing_accounts(self, userName):
        self.requires_token()
        resource = '/user/%s/billing/' % userName
        request = Request(token=self.get_token())
        content = request.get(resource)
        return json.loads(content)


class ConnectionException(Exception):
    pass


class TokenRequiredError(Exception):
    def __str__(self):
        return unicode(self).encode()

    def __unicode__(self):
        return u'No valid token. Use create_token(email, password) to get one'


class BadRequestError(Exception):
    def __init__(self, value):
        try:
            self.msgs = json.loads(value[12:])
        except ValueError:
            self.msgs = {}

    def __str__(self):
        return unicode(self).encode()

    def __unicode__(self):
        return u''.join(u'%s: %s\n' for item in self.msgs.iteritems()) or u'Bad Request'


class UnauthorizedError(Exception):
    pass


class ForbiddenError(Exception):
    pass


class NotFoundError(Exception):
    pass


class ConflictDuplicateError(Exception):
    pass


class GoneError(Exception):
    pass


class InternalServerError(Exception):
    pass


class NotImplementedError(Exception):
    pass


class ThrottledError(Exception):
    pass


class Request():
    """
        Request is used internally to actually fire API requests. It has some
        handy shortcut methods for POST, GET, PUT and DELETE, sets correct
        headers for each method, takes care of encoding data and handles all
        API errors by throwing exceptions.
    """
    email = None
    password = None
    token = None
    version = None
    url = None
    disable_ssl_check = None
    ca_certs = None

    def __init__(self, email=None, password=None, token=None):
        """
            When initializing a Request object decide if token auth or email,
            password auth should be used. The class handles both cases
            accordingly.
        """
        self.email = email
        self.password = password
        self.token = token
        self.version = VERSION
        self.url = API_URL
        self.disable_ssl_check = DISABLE_SSL_CHECK
        self.ca_certs = CA_CERTS

    def post(self, resource, data=None):
        return self.request(resource, method='POST', data=data)

    def get(self, resource):
        return self.request(resource)

    def put(self, resource, data=None):
        return self.request(resource, method='PUT', data=data)

    def delete(self, resource):
        return self.request(resource, method='DELETE')

    def request(self, resource, method='GET', data=None, headers=None):
        """
            we use the excellent httplib2 for all the heavy HTTP protocol
            lifting.
        """
        method = method.upper()
        if not headers:
            headers = {}
        url = urlparse(self.url + resource)
        h = httplib2.Http()

        if self.disable_ssl_check:
            h.disable_ssl_certificate_validation = self.disable_ssl_check

        if self.ca_certs:
            h.ca_certs = self.ca_certs

        #
        # If the current API instance has a valid token we add
        # the Authorization
        # header with the correct token.
        #
        # In case we do not have a valid token but email and password are
        # provided we automatically use them to add a HTTP Basic Authentication
        # header to the request to create a new token.
        #
        if self.token is not None:
            headers['Authorization'] = 'cc_auth_token="%s"' % \
                (self.token['token'])
        elif self.email is not None and self.password is not None:
            h.add_credentials(self.email, self.password)
        #
        # The API expects the body to be url-encoded. If data was passed to
        # the request method we therefore use url-encode from urllib.
        #
        body = urlencode(data) if data else ''

        #
        # We set the User-Agent Header to pycclib and the local version.
        # This enables basic statistics about still used pycclib versions in
        # the wild.
        #
        headers['User-Agent'] = 'pycclib/%s' % self.version
        headers['Accept-Charset'] = 'utf-8'
        #
        # The API expects PUT or POST data to be x-www-form-urlencoded so we
        # also set the correct Content-Type header.
        #
        if method in ('PUT', 'POST'):
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        #
        # Finally we fire the actual request.
        #
        try:
            resp, content = h.request(url.geturl(), method, body=body, headers=headers)
        except httplib2.SSLHandshakeError:
            raise ConnectionException('Certificate verification failed ...')

        content = content.decode('utf-8')
        if resp.status in [200, 201, 204]:
            return content
        exc_for_code = {
            400: BadRequestError,
            401: UnauthorizedError,
            403: ForbiddenError,
            404: NotFoundError,
            409: ConflictDuplicateError,
            410: GoneError,
            500: InternalServerError,
            501: NotImplementedError,
            503: ThrottledError,
        }
        raise exc_for_code.get(resp.status, Exception)(content)
