# -*- coding: utf-8 -*-
"""
pycclib

library for accessing the cloudControl API using Python

Copyright 2010 cloudControl UG (haftungsbeschraenkt)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### basic usage example
# from pycclib.cclib import *
#
# api = API()
# api.create_token(email='name@example.com', password='secretpassword')
#
# apps = api.read_apps()

"""
import base64
from urlparse import urlparse
import calendar
import urllib
# python versions below 2.6 do not have json included we need simplejson then

try:
    import json
except ImportError:
    import simplejson as json

import time
from urllib import urlencode
import socket
from decimal import Decimal

import certifi
import httplib2

from pycclib.version import __version__
# We avoid the potential risk of somebody relying on the deprecated apiurl.py
# by raising an exception to make sure nobody talks to the wrong API due to
# our backwards incompatible change.
try:
    from pycclib import apiurl
except ImportError:
    pass
else:
    raise Exception('Use of apiurl.py is deprecated. Set pycclib.API_URL instead.')

__all__ = ['API', 'UnauthorizedError', 'ConnectionException',
           'TokenRequiredError', 'BadRequestError', 'ForbiddenError',
           'ConflictDuplicateError', 'GoneError', 'InternalServerError',
           'NotImplementedError', 'ThrottledError']

API_URL = 'https://api.cloudcontrolled.com'
DISABLE_SSL_CHECK = False
CA_CERTS = None
CACHE = None
# Set debug to 1 to enable debugging
DEBUG = 0
VERSION = __version__


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
    request = None
    cache = None

    def __init__(self, token=None, url=None, token_source_url=None, register_addon_url=None, encode_email=False):
        self.set_token(token)
        api_url = url or API_URL
        self.request = _Request(url=api_url)
        self.token_source_url = token_source_url or api_url + '/token/'
        if token:
            self.request.set_token_authorization_header(token)
        self.register_addon_url = register_addon_url or api_url
        self.encode_email = encode_email

    def check_versions(self):
        version_request = _Request(url=self.request.url)
        content = version_request.get('/.meta/version/')
        return json.loads(content)

    def requires_token(self):
        """
            requires_token checks that methods that require
            a token can't be called without a token.

            If check_token doesn't return True a TokenRequiredError exception
            is raised telling the caller to use the create_token method to get
            a valid token.
        """
        if not self.check_token():
            raise TokenRequiredError

    def create_token(self, email, password):
        """
            Sends token creation request to API using basic auth - for backwards compatibility
        """
        return self.create_token_basic_auth(email, password)

    def create_token_basic_auth(self, email, password):
        """
            Sends token creation request to API using basic auth
        """
        token_request = _Request(url=self.token_source_url)
        token_request.set_basic_authorization_header(email, password, self.encode_email)
        return self.token_request(token_request)

    def create_token_ssh_auth(self, email, ssh_token, signature, fingerprint):
        """
            Sends token creation request to API using ssh auth
        """
        token_request = _Request(url=self.token_source_url)
        token_request.set_sshtoken_authorization_header(email, ssh_token, signature, fingerprint)
        return self.token_request(token_request)

    def token_request(self, token_request):
        content = token_request.request('', 'POST')
        token = json.loads(content)
        self.set_token(token)
        self.request.set_token_authorization_header(token)
        return True

    def create_ssh_token(self):
        try:
            token_request = _Request(url=self.token_source_url)
            token_request.request('', 'POST')
            raise APIException('Expected UnauthorizedError has not been raised')

        except UnauthorizedError as e:
            result = httplib2._parse_www_authenticate(e.response)

            try:
                ssh_token = result['ccssh']['sshtoken']
            except KeyError, TypeError:
                raise APIException('SSH token was not created')

            if not ssh_token:
                raise APIException('Empty SSH token.')

            return ssh_token

    def check_token(self):
        """
            This method checks if there's a token.
        """
        if self.request.token:
            return True

        return False

    def set_token(self, token):
        """
            We use set_token to set the token.
        """
        self._token = token

    def get_token(self):
        """
            We use get_token to get the token.
        """
        return self._token

    def create_app(self, app_name, type, repository_type, buildpack_url=None):
        """
            Create a new application and return it.
        """
        self.requires_token()
        resource = '/app/'
        data = {'name': app_name,
                'type': type,
                'repository_type': repository_type}
        if buildpack_url:
                data['buildpack_url'] = buildpack_url

        content = self.request.post(resource, data)
        return json.loads(content)

    def read_apps(self):
        """
            Returns a list of applications.
        """
        self.requires_token()
        resource = '/app/'
        content = self.request.get(resource)
        return json.loads(content)

    def read_app(self, app_name):
        """
            Returns all application details.
        """
        self.requires_token()
        resource = '/app/%s/' % app_name
        content = self.request.get(resource)
        return json.loads(content)

    def delete_app(self, app_name):
        """
            Delete a application.
        """
        self.requires_token()
        resource = '/app/%s/' % app_name
        self.request.delete(resource)
        return True

    def create_deployment(self, app_name, deployment_name='', stack=None):
        """
            Create a new deployment.

            deployment_name is optional
        """
        self.requires_token()
        resource = '/app/%s/deployment/' % app_name
        data = {}
        if deployment_name:
            data['name'] = deployment_name
        if stack:
            data['stack'] = stack
        content = self.request.post(resource, data)
        return json.loads(content)

    def read_deployment(self, app_name, deployment_name):
        """
            Returns all deployment details.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        content = self.request.get(resource)
        return json.loads(content)

    def read_deployment_users(self, app_name, deployment_name):
        """
            get a list of the deployment-users
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/user/' % (app_name, deployment_name)
        content = self.request.get(resource)
        return json.loads(content)

    def update_deployment(self, app_name, version=-1, deployment_name='',
                          min_boxes=None, max_boxes=None, billing_account=None,
                          stack=None):
        """
            Updates a deployment.

            Use this to deploy new versions. If no version is provided the
            last version is deployed.
        """
        self.requires_token()
        if deployment_name == '':
            deployment_name = 'default'
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        data = {'version': version}
        if min_boxes:
            data['min_boxes'] = min_boxes
        if max_boxes:
            data['max_boxes'] = max_boxes
        if billing_account:
            data['billing_account'] = billing_account
        if stack:
            data['stack'] = stack
        content = self.request.put(resource, data)
        return json.loads(content)

    def delete_deployment(self, app_name, deployment_name):
        """
            Delete a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/' % (app_name, deployment_name)
        self.request.delete(resource)
        return True

    def create_alias(self, app_name, alias_name, deployment_name):
        """
            Add an alias to a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/' % (app_name, deployment_name)
        data = {'name': alias_name}
        content = self.request.post(resource, data)
        return json.loads(content)

    def read_aliases(self, app_name=None, deployment_name=None):
        """
            Get a list of aliases.
        """
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/alias/' % \
                (app_name, deployment_name)
            content = self.request.get(resource)
        return json.loads(content)

    def read_alias(self, app_name, alias_name, deployment_name):
        """
            Get all alias details.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/%s/' % \
            (app_name, deployment_name, alias_name)
        content = self.request.get(resource)
        return json.loads(content)

    def delete_alias(self, app_name, alias_name, deployment_name):
        """
            Remove an alias from a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/alias/%s/' % \
            (app_name, deployment_name, alias_name)
        self.request.delete(resource)
        return True

    def create_worker(self, app_name, deployment_name, command, params=None, size=None):
        """
            Add an worker to a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/' % \
            (app_name, deployment_name)
        data = {'command': command}
        if params:
            data['params'] = params
        if size:
            data['size'] = size
        content = self.request.post(resource, data)
        return json.loads(content)

    def read_workers(self, app_name=None, deployment_name=None):
        """
            Get a list of runnnig workers for a deployment.
        """
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/worker/' % \
                (app_name, deployment_name)
            content = self.request.get(resource)
        return json.loads(content)

    def read_worker(self, app_name, deployment_name, wrk_id):
        """
            Get all worker details.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/%s/' % \
            (app_name, deployment_name, wrk_id)
        content = self.request.get(resource)
        return json.loads(content)

    def delete_worker(self, app_name, deployment_name, wrk_id):
        """
            Remove an worker from a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/worker/%s/' % \
            (app_name, deployment_name, wrk_id)
        self.request.delete(resource)
        return True

    def create_cronjob(self, app_name, deployment_name, url):
        """
            Add an worker to a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/' % (app_name, deployment_name)
        data = {'url': url}
        content = self.request.post(resource, data)
        return json.loads(content)

    def read_cronjobs(self, app_name=None, deployment_name=None):
        """
            Get a list of cronjobs.
        """
        content = None
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/cron/' % \
                (app_name, deployment_name)
            content = self.request.get(resource)
        return json.loads(content)

    def read_cronjob(self, app_name, deployment_name, job_id):
        """
            Get all worker details.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/%s/' % \
            (app_name, deployment_name, job_id)
        content = self.request.get(resource)
        return json.loads(content)

    def delete_cronjob(self, app_name, deployment_name, job_id):
        """
            Remove an worker from a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/cron/%s/' % \
            (app_name, deployment_name, job_id)
        self.request.delete(resource)
        return True

    def register_addon(self, email, password, data):
        """
            Register a new addon on the platform.

            The addon manifest content needs to be passed via the data argument.
        """
        request = _Request(url=self.register_addon_url)
        request.set_basic_authorization_header(email, password, encode_email=self.encode_email)
        content = request.post('/provider/addons', data, json_data=True)
        return json.loads(content)

    def create_addon(self, app_name, deployment_name, addon_name, options=None):
        """
            Add an addon to a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/' % (app_name, deployment_name)
        data = {'addon': addon_name}
        if options:
            data['options'] = options
        content = self.request.post(resource, data)
        return json.loads(content)

    def read_addons(self, app_name=None, deployment_name=None):
        """
            Get a list of addons.

            If app_name and deployment_name are None it will return a list
            of available addons. Otherwise a list of addons related to that
            deployment.
        """
        if app_name and deployment_name:
            self.requires_token()
            resource = '/app/%s/deployment/%s/addon/' % \
                (app_name, deployment_name)
            content = self.request.get(resource)
        else:
            resource = '/addon/'
            content = self.request.get(resource)
        return json.loads(content)

    def read_addon(self, app_name, deployment_name, addon_name):
        """
            Get all addon details.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name)
        content = self.request.get(resource)
        return json.loads(content)

    def update_addon(self, app_name, deployment_name, addon_name_current,
                     addon_name_to_update_to, settings=None, force=False):
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name_current)
        data = {'addon': addon_name_to_update_to}
        if settings:
            data['settings'] = settings
        if force:
            data['force'] = force
        content = self.request.put(resource, data)
        return json.loads(content)

    def delete_addon(self, app_name, deployment_name, addon_name):
        """
            Remove an addon from a deployment.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/addon/%s/' % \
            (app_name, deployment_name, addon_name)
        self.request.delete(resource)
        return True

    def read_app_users(self, app_name):
        """
            Get a list of app users.
        """
        self.requires_token()
        resource = '/app/%s/user/' % app_name
        content = self.request.get(resource)
        return json.loads(content)

    def create_app_user(self, app_name, email, role=None):
        """
            Add a user to an application.
        """
        self.requires_token()
        resource = '/app/%s/user/' % app_name
        data = {'email': email}
        if role:
            data['role'] = role

        content = self.request.post(resource, data)
        return json.loads(content)

    def delete_app_user(self, app_name, user_name):
        """
           Remove a user from an application.
        """
        self.requires_token()
        resource = '/app/%s/user/%s/' % (app_name, user_name)
        self.request.delete(resource)
        return True

    def create_deployment_user(self, app_name, deployment_name, email, role=None):
        """
            Add a user to an application.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/user/' % (app_name, deployment_name)
        data = {'email': email}
        if role:
            data['role'] = role

        content = self.request.post(resource, data)
        return json.loads(content)

    def delete_deployment_user(self, app_name, deployment_name, user_name):
        """
           Remove a user from an application.
        """
        self.requires_token()
        resource = '/app/%s/deployment/%s/user/%s/' % (app_name, deployment_name, user_name)
        self.request.delete(resource)
        return True

    def read_users(self):
        """
            Get a list of users. Usually just your own.
        """
        self.requires_token()
        resource = '/user/'
        content = self.request.get(resource)
        return json.loads(content)

    def create_user(self, name, email, password):
        """
            Create a new user.
        """
        resource = '/user/'
        user_request = _Request(url=self.request.url)
        data = {
            'username': name,
            'email': email,
            'password': password}
        content = user_request.post(resource, data)
        return json.loads(content)

    def read_user(self, user_name):
        """
            Get user by user_name.
        """
        self.requires_token()
        resource = '/user/%s/' % user_name
        content = self.request.get(resource)
        return json.loads(content)

    def update_user(self, user_name, activation_code=None):
        """
            Update user by user_name.

            Use this for activation after registration.
        """
        resource = '/user/%s/' % user_name
        if activation_code:
            user_request = _Request(url=self.request.url)
            data = {'activation_code': activation_code}
            user_request.put(resource, data)
        else:
            # Not implemented yet
            return False
        return True

    def delete_user(self, user_name):
        """
            Delete user by user_name.
        """
        self.requires_token()
        resource = '/user/%s/' % user_name
        self.request.delete(resource)
        return True

    def read_user_keys(self, user_name):
        """
            Get a list of keys belonging to user selected by user_name.
        """
        self.requires_token()
        resource = '/user/%s/key/' % user_name
        content = self.request.get(resource)
        return json.loads(content)

    def read_user_key(self, user_name, key_id):
        """
            Get a key by user_name and key_id.
        """
        self.requires_token()
        resource = '/user/%s/key/%s/' % (user_name, key_id)
        content = self.request.get(resource)
        return json.loads(content)

    def create_user_key(self, user_name, public_key):
        """
            Add a key to user by user_name.
        """
        self.requires_token()
        resource = '/user/%s/key/' % user_name
        data = {'key': public_key}
        content = self.request.post(resource, data)
        return json.loads(content)

    def delete_user_key(self, user_name, key_id):
        """
            Remove a key from user by user_name.

            Requires key_id that can be requested using read_user_keys()
        """
        self.requires_token()
        resource = '/user/%s/key/%s/' % (user_name, key_id)
        self.request.delete(resource)
        return True

    def read_log(self, app_name, deployment_name, log_type, last_time=None):
        """
            Get a deployment's log by log_type.

            log_type choices are 'access' or 'error'

            last_time is optional format is a Python datetime object or a time struct
        """
        self.requires_token()
        if last_time:
            try:
                last_time_tuple = last_time.timetuple()
                timestamp = Decimal('{0}.{1}'.format(int(time.mktime(last_time_tuple)), last_time.microsecond))
            except (TypeError, AttributeError):
                timestamp = calendar.timegm(last_time)

            resource = '/app/%s/deployment/%s/log/%s/?timestamp=%s' % \
                (app_name, deployment_name, log_type, timestamp)
        else:
            resource = '/app/%s/deployment/%s/log/%s/' % \
                (app_name, deployment_name, log_type)
        content = self.request.get(resource)
        return json.loads(content)

    def create_billing_account(self, userName, billingName, data):
        """
        creates a billing account.
        """
        self.requires_token()
        resource = '/user/%s/billing/%s/' % (userName, billingName)
        content = self.request.post(resource, data)
        return json.loads(content)

    def update_billing_account(self, userName, billingName, data):
        """
        updates a billing account
        """
        self.requires_token()
        resource = '/user/%s/billing/%s/' % (userName, billingName)
        content = self.request.put(resource, data)
        return json.loads(content)

    def get_billing_accounts(self, userName):
        """
        return all users billling accounts
        """
        self.requires_token()
        resource = '/user/%s/billing/' % userName
        content = self.request.get(resource)
        return json.loads(content)

###
#
# EXCEPTIONS
#
###


class APIException(Exception):

    response = None

    def __init__(self, message=None, resp=None):
        super(Exception, self).__init__(message)
        self.response = resp


class ConnectionException(APIException):
    """
        We raise this exception if the API was unreachable.
    """
    pass


class TokenRequiredError(APIException):
    """
        We raise this exception if a method requires a token but self._token
        is none.

        Use the create_token() method to get a new token.
    """
    #noinspection PyMethodOverriding
    def __unicode__(self):
        return 'No valid token. Use create_token(email, password) to get one'


class BadRequestError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 400
        BAD REQUEST.
    """

    msgs = {}

    #noinspection PyMissingConstructor
    def __init__(self, value):
        try:
            try:
                self.msgs = json.loads(value)
            except ValueError:
                self.msgs = json.loads(value[12:])
        except ValueError:
            self.msgs = {}

    def __str__(self):
        msg = ''
        for key in self.msgs:
            msg = msg + key + ': ' + self.msgs[key] + '\n'
        return msg


class UnauthorizedError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 401
        UNAUTHORIZED.
    """
    pass


class ForbiddenError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 403
        FORBIDDEN.
    """
    pass


class NotFoundError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 404
        NOT FOUND.
    """
    pass


class ConflictDuplicateError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 409
        DUPLICATE ENTRY.
    """
    pass


class GoneError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 410
        GONE.
    """
    pass


class InternalServerError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 500
        INTERNAL SERVER ERROR.
    """
    pass


class NotImplementedError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 501
        NOT IMPLEMENTED.
    """
    pass


class ThrottledError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 503
        THROTTLED.
    """
    msgs = {}

    #noinspection PyMissingConstructor
    def __init__(self, value):
        self.prefix_with_error = True
        try:
            try:
                self.msgs = json.loads(value)
            except ValueError:
                self.msgs = json.loads(value[12:])
        except ValueError:
            self.msgs = {'error': value}
            self.prefix_with_error = False

    def __str__(self):
        msg = ''
        for key in self.msgs:
            if self.prefix_with_error:
                msg += "[ERROR] "
            msg += self.msgs[key] + '\n'
        return msg[:-1]


class UnprocessableEntityError(APIException):
    """
        We raise this exception whenever the API answers with HTTP STATUS 422
        UNPROCESSABLE ENTITY.
    """
    pass


class BadGatewayError(APIException):
    pass


class GatewayTimeoutError(APIException):
    pass


###
#
# _Request Class using httplib2 to fire HTTP requests
#
###


class _Request():
    """
        _Request is used internally to actually fire API requests. It has some
        handy shortcut methods for POST, GET, PUT and DELETE, sets correct
        headers for each method, takes care of encoding data and handles all
        API errors by throwing exceptions.
    """
    token = None
    version = None
    cache = None
    url = None
    disable_ssl_check = None
    ca_certs = None

    def __init__(self, url=API_URL):
        """
            When initializing a _Request object decide if ssh auth, token auth or email,
            password auth should be used. The class handles both cases
            accordingly.
        """
        self.version = VERSION
        self.cache = CACHE
        self.url = url
        self.disable_ssl_check = DISABLE_SSL_CHECK
        self.ca_certs = CA_CERTS or certifi.where()
        self.headers = {}

    def post(self, resource, data=None, json_data=False):
        if not data:
            data = {}

        return self.request(resource, method='POST', data=data, json_data=json_data)

    def get(self, resource):
        return self.request(resource)

    def put(self, resource, data=None):
        if not data:
            data = {}

        return self.request(resource, method='PUT', data=data)

    def delete(self, resource):
        return self.request(resource, method='DELETE')

    def set_basic_authorization_header(self, email, password, encode_email=False):
        if encode_email:
            email = urllib.quote(email)
        self.headers['Authorization'] = 'Basic ' + base64.b64encode("%s:%s" % (email, password)).strip()

    def set_token_authorization_header(self, token):
        self.token = token
        self.headers['Authorization'] = 'cc_auth_token="%s"' % (token['token'])

    def set_sshtoken_authorization_header(self, email, ssh_token, signature, fingerprint):
        auth_string = 'signature={0},fingerprint={1},sshtoken={2},email={3}'.format(
            signature, fingerprint, ssh_token, email)
        self.headers['Authorization'] = 'ccssh ' + auth_string

    def request(self, resource, method='GET', data=None, headers=None, json_data=False):
        """
            we use the excellent httplib2 for all the heavy HTTP protocol
            lifting.
        """
        if headers:
            self.headers.update(headers)

        url = urlparse(self.url + resource)
        h = httplib2.Http()

        if self.cache:
            h.cache = self.cache

        if self.disable_ssl_check:
            h.disable_ssl_certificate_validation = self.disable_ssl_check

        if self.ca_certs:
            h.ca_certs = self.ca_certs

        #
        # The API expects the body to be url-encoded. If data was passed to
        # the request method we therefore use url-encode from urllib.
        #
        if data is None:
            body = ''
        else:
            if json_data:
                body = json.dumps(data)
            else:
                body = urlencode(data)

        #
        # We set the Host Header for MacOSX 10.5,
        # to circumvent the NotFoundError
        #
        self.headers['Host'] = url.hostname
        #
        # We set the User-Agent Header to pycclib and the local version.
        # This enables basic statistics about still used pycclib versions in
        # the wild.
        #
        self.headers['User-Agent'] = 'pycclib/%s' % self.version

        if method.upper() == 'PUT' or 'POST':
            if json_data:
                self.headers['Content-Type'] = 'application/json'
            else:
                self.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        #
        # We also set the Content-Length and Accept-Encoding headers.
        #
        self.headers['Content-Length'] = str(len(body))
        self.headers['Accept-Encoding'] = 'compress, gzip'

        #
        # Debug HTTP requests
        if DEBUG:
            httplib2.debuglevel = DEBUG

        #
        # Finally we fire the actual request.
        #
        resp = None
        content = None
        for i in range(1, 6):
            try:
                resp, content = h.request(
                    url.geturl(),
                    method.upper(),
                    body=body,
                    headers=self.headers)

                if DEBUG:
                    print 'DEBUG(resp)>>> {0}'.format(repr(resp))
                    print 'DEBUG(content)>>> {0}'.format(repr(content))

            except (socket.error, AttributeError), e:
                # if we could not reach the API we wait 1s and try again
                time.sleep(1)
                # if we tried for the fifth time we give up - and cry a little
                if i == 5:
                    if DEBUG:
                        print 'DEBUG(exception)>>> {0}'.format(e)
                    raise ConnectionException('Could not connect to API...')
            except httplib2.SSLHandshakeError:
                raise ConnectionException('Certificate verification failed ...')
            else:
                break
        #
        # And handle the possible responses according to their HTTP STATUS
        # CODES.
        #
        # 200 OK, 201 CREATED and 204 DELETED result in returning the actual
        # response.
        #
        # All non success STATUS CODES raise an exception containing
        # the API error message.
        #

        if resp.status in [200, 201, 204]:
            return content.decode('UTF8')
        elif resp.status == 400:
            raise BadRequestError(content.decode('UTF8'))
        elif resp.status == 401:
            raise UnauthorizedError(content.decode('UTF8'), resp)
        elif resp.status == 403:
            raise ForbiddenError(content.decode('UTF8'))
        elif resp.status == 404:
            raise NotFoundError()
        elif resp.status == 409:
            raise ConflictDuplicateError(content.decode('UTF8'))
        elif resp.status == 410:
            raise GoneError(content.decode('UTF8'))
        elif resp.status == 422:
            raise UnprocessableEntityError(content.decode('UTF8'))
        #
        # 500 INTERNAL SERVER ERRORs normally shouldn't happen...
        #
        elif resp.status == 500:
            raise InternalServerError(content.decode('UTF8'))
        elif resp.status == 501:
            raise NotImplementedError(content.decode('UTF8'))
        elif resp.status == 502:
            raise BadGatewayError(content.decode('UTF-8'))
        elif resp.status == 503:
            raise ThrottledError(content.decode('UTF8'))
        elif resp.status == 504:
            raise GatewayTimeoutError(content.decode('UTF-8'))
        else:
            raise Exception('Received unexpected response status: %s' % str(resp.status))
