import json
import logging
import warnings

try:
    from urllib.parse import urljoin, urlsplit
except ImportError:
    from urlparse import urljoin, urlsplit

from requests import delete, get, head, post, put
from requests.exceptions import HTTPError

from .AuthorizationService import AuthorizationService
from .manifest import sign as sign_manifest


# Module setup

# urllib3 throws some ssl warnings with older versions of python
#   they're probably ok for the registry client to ignore
warnings.filterwarnings("ignore", module="urllib3", append=True)

logger = logging.getLogger(__name__)


class CommonBaseClient(object):
    def __init__(self, host, verify_ssl=None, username=None, password=None,
                 api_timeout=None):
        self.host = host

        self.method_kwargs = {}
        if verify_ssl is not None:
            self.method_kwargs['verify'] = verify_ssl
        if username is not None and password is not None:
            self.method_kwargs['auth'] = (username, password)
        if api_timeout is not None:
            self.method_kwargs['timeout'] = api_timeout

    def _http_response(self, url, method, data=None, **kwargs):
        """url -> full target url
           method -> method from requests
           data -> request body
           kwargs -> url formatting args
        """
        header = {'content-type': 'application/json'}

        if data:
            data = json.dumps(data)
        path = url.format(**kwargs)
        logger.debug("%s %s", method.__name__.upper(), path)
        response = method(self.host + path,
                          data=data, headers=header, **self.method_kwargs)
        logger.debug("%s %s", response.status_code, response.reason)
        response.raise_for_status()

        return response

    def _http_call(self, url, method, data=None, **kwargs):
        """url -> full target url
           method -> method from requests
           data -> request body
           kwargs -> url formatting args
        """
        response = self._http_response(url, method, data=data, **kwargs)
        if not response.content:
            return {}

        return response.json()


class BaseClientV1(CommonBaseClient):
    IMAGE_LAYER = '/v1/images/{image_id}/layer'
    IMAGE_JSON = '/v1/images/{image_id}/json'
    IMAGE_ANCESTRY = '/v1/images/{image_id}/ancestry'
    REPO = '/v1/repositories/{namespace}/{repository}'
    TAGS = REPO + '/tags'

    @property
    def version(self):
        return 1

    def search(self, q=''):
        """GET /v1/search"""
        if q:
            q = '?q=' + q
        return self._http_call('/v1/search' + q, get)

    def check_status(self):
        """GET /v1/_ping"""
        return self._http_call('/v1/_ping', get)

    def get_images_layer(self, image_id):
        """GET /v1/images/{image_id}/layer"""
        return self._http_call(self.IMAGE_LAYER, get, image_id=image_id)

    def put_images_layer(self, image_id, data):
        """PUT /v1/images/(image_id)/layer"""
        return self._http_call(self.IMAGE_LAYER, put,
                               image_id=image_id, data=data)

    def put_image_layer(self, image_id, data):
        """PUT /v1/images/(image_id)/json"""
        return self._http_call(self.IMAGE_JSON, put,
                               data=data, image_id=image_id)

    def get_image_layer(self, image_id):
        """GET /v1/images/(image_id)/json"""
        return self._http_call(self.IMAGE_JSON, get, image_id=image_id)

    def get_image_ancestry(self, image_id):
        """GET /v1/images/(image_id)/ancestry"""
        return self._http_call(self.IMAGE_ANCESTRY, get, image_id=image_id)

    def get_repository_tags(self, namespace, repository):
        """GET /v1/repositories/(namespace)/(repository)/tags"""
        return self._http_call(self.TAGS, get,
                               namespace=namespace, repository=repository)

    def get_image_id(self, namespace, respository, tag):
        """GET /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, get,
                               namespace=namespace, repository=respository)

    def get_tag_json(self, namespace, repository, tag):
        """GET /v1/repositories(namespace)/(repository)tags(tag*)/json"""
        return self._http_call(self.TAGS + '/' + tag + '/json', get,
                               namespace=namespace, repository=repository)

    def delete_repository_tag(self, namespace, repository, tag):
        """DELETE /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, delete,
                               namespace=namespace, repository=repository)

    def set_tag(self, namespace, repository, tag, image_id):
        """PUT /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, put, data=image_id,
                               namespace=namespace, repository=repository)

    def delete_repository(self, namespace, repository):
        """DELETE /v1/repositories/(namespace)/(repository)/"""
        return self._http_call(self.REPO, delete,
                               namespace=namespace, repository=repository)


class _Manifest(object):
    def __init__(self, content, type, digest):
        self._content = content
        self._type = type
        self._digest = digest


BASE_CONTENT_TYPE = 'application/vnd.docker.distribution.manifest'


class BaseClientV2(CommonBaseClient):
    LIST_TAGS = '/v2/{name}/tags/list'
    MANIFEST = '/v2/{name}/manifests/{reference}'
    BLOB = '/v2/{name}/blobs/{digest}'
    BLOB_MOUNT = '/v2/{name}/blobs/uploads/?mount={digest}&from={origin}'
    schema_1_signed = BASE_CONTENT_TYPE + '.v1+prettyjws'
    schema_1 = BASE_CONTENT_TYPE + '.v1+json'
    schema_2 = BASE_CONTENT_TYPE + '.v2+json'

    def __init__(self, *args, **kwargs):
        host = args[0]

        # Default to the main part of the repository hostname if the service name is missing
        # or None (the default)
        auth_service_name = kwargs.pop("auth_service_name", "") or urlsplit(host).netloc

        # Get the URL of the auth service from the args, accounting for the deprecated url arg
        auth_service_url = kwargs.pop("auth_service_url_full", "")
        deprecated_auth_service_url_arg = kwargs.pop("auth_service_url", "")

        if deprecated_auth_service_url_arg:
            warnings.warn(
                'The auth_service_url argument is deprecated; use auth_service_url_full instead',
                DeprecationWarning,
            )
            if not auth_service_url:
                auth_service_url = urljoin(deprecated_auth_service_url_arg, 'v2/token')

        super(BaseClientV2, self).__init__(*args, **kwargs)

        # If we are using token authentication with v2, we use the username
        # and pw only for the authorization service and not for the registry
        # itself.
        #
        # We must pop the auth kwarg so it does not get sent to requests,
        # because override the authentication token if it sees the username/password
        # provided
        # See: http://docs.python-requests.org/en/master/user/quickstart/#custom-headers
        if auth_service_url:
            auth = self.method_kwargs.pop('auth', None)
        else:
            auth = self.method_kwargs.get('auth')

        self._manifest_digests = {}
        self.auth = AuthorizationService(
            service_name=auth_service_name,
            url=auth_service_url,
            verify=self.method_kwargs.get('verify', False),
            auth=auth,
            api_timeout=self.method_kwargs.get('api_timeout')
        )

    @property
    def version(self):
        return 2

    def check_status(self):
        self.auth.desired_scope = ''
        return self._http_call('/v2/', get)

    def catalog(self):
        self.auth.desired_scope = 'registry:catalog:*'
        return self._http_call('/v2/_catalog', get)

    def get_repository_tags(self, name):
        self.auth.desired_scope = 'repository:%s:*' % name
        return self._http_call(self.LIST_TAGS, get, name=name)

    def get_manifest_and_digest(self, name, reference):
        m = self.get_manifest(name, reference)
        return m._content, m._digest

    def get_manifest(self, name, reference):
        self.auth.desired_scope = 'repository:%s:*' % name
        response = self._http_response(
            self.MANIFEST, get, name=name, reference=reference,
            schema=self.schema_1_signed,
        )
        self._cache_manifest_digest(name, reference, response=response)
        return _Manifest(
            content=response.json(),
            type=response.headers.get('Content-Type', 'application/json'),
            digest=self._manifest_digests[name, reference],
        )

    def check_manifest(self, name, reference):
        self.auth.desired_scope = 'repository:%s:*' % name
        response = self._http_response(
            self.MANIFEST, head, name=name, reference=reference,
            schema=self.schema_1_signed,
        )
        self._cache_manifest_digest(name, reference, response=response)
        return response.ok

    def put_manifest(self, name, reference, manifest):
        self.auth.desired_scope = 'repository:%s:*' % name
        content = {}
        content.update(manifest._content)

        content['name'] = name

        # If reference is a tag, update it; otherwise, leave the tag as is
        if not reference.startswith('sha256:'):
            content['tag'] = reference

        return self._http_call(
            self.MANIFEST, put, data=sign_manifest(content),
            content_type=self.schema_1_signed, schema=self.schema_1_signed,
            name=name, reference=reference,
        )

    def delete_manifest(self, name, digest):
        self.auth.desired_scope = 'repository:%s:*' % name
        return self._http_call(self.MANIFEST, delete,
                               name=name, reference=digest)

    def copy_blob(self, origin, digest, destination):
        self.auth.desired_scope = ['repository:%s:*' % repo for repo in (origin, destination)]
        return self._http_call(self.BLOB_MOUNT, post,
                               name=destination, digest=digest, origin=origin)

    def delete_blob(self, name, digest):
        self.auth.desired_scope = 'repository:%s:*' % name
        return self._http_call(self.BLOB, delete,
                               name=name, digest=digest)

    def _cache_manifest_digest(self, name, reference, response=None):
        if not response:
            # TODO: create our own digest
            raise NotImplementedError()

        untrusted_digest = response.headers.get('Docker-Content-Digest')
        self._manifest_digests[(name, reference)] = untrusted_digest

    def _http_response(self, url, method, data=None, content_type=None,
                       schema=None, **kwargs):
        """url -> full target url
           method -> method from requests
           data -> request body
           kwargs -> url formatting args
        """

        if schema is None:
            schema = self.schema_2

        header = {
            'content-type': content_type or 'application/json',
            'Accept': schema,
        }

        # Token specific part. We add the token in the header if necessary
        auth = self.auth
        token_required = auth.token_required
        token = auth.token
        desired_scope = auth.desired_scope
        scope = auth.scope

        if token_required:
            if not token or desired_scope != scope:
                logger.debug("Getting new token for scope: %s", desired_scope)
                auth.get_new_token()

            header['Authorization'] = 'Bearer %s' % self.auth.token

        if data and not content_type:
            data = json.dumps(data)

        path = url.format(**kwargs)
        logger.debug("%s %s", method.__name__.upper(), path)
        response = method(self.host + path,
                          data=data, headers=header, **self.method_kwargs)
        logger.debug("%s %s", response.status_code, response.reason)

        try:
            response.raise_for_status()
        except HTTPError as e:
            if e.response.content:
                logger.error('Error Response: {}'.format(response.content))
            raise

        return response


def BaseClient(host, verify_ssl=None, api_version=None, username=None, password=None,
               auth_service_url="", auth_service_url_full="", auth_service_name=None,
               api_timeout=None):
    if api_version == 1:
        return BaseClientV1(
            host, verify_ssl=verify_ssl, username=username, password=password,
            api_timeout=api_timeout,
        )
    elif api_version == 2:
        return BaseClientV2(
            host, verify_ssl=verify_ssl, username=username, password=password,
            auth_service_url=auth_service_url, auth_service_url_full=auth_service_url_full,
            auth_service_name=auth_service_name, api_timeout=api_timeout,
        )
    elif api_version is None:
        # Try V2 first
        logger.debug("checking for v2 API")
        v2_client = BaseClientV2(
            host, verify_ssl=verify_ssl, username=username, password=password,
            auth_service_url=auth_service_url, auth_service_url_full=auth_service_url_full,
            auth_service_name=auth_service_name, api_timeout=api_timeout,
        )
        try:
            v2_client.check_status()
        except HTTPError as e:
            if e.response.status_code == 404:
                logger.debug("falling back to v1 API")
                return BaseClientV1(
                    host, verify_ssl=verify_ssl, username=username,
                    password=password, api_timeout=api_timeout,
                )

            raise
        else:
            logger.debug("using v2 API")
            return v2_client
    else:
        raise RuntimeError('invalid api_version')
