"""
Copyright 2015 Red Hat, Inc

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


from __future__ import absolute_import

import argparse
import json
import logging
import warnings

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


import requests

from docker_registry_client import DockerRegistryClient


class CLI(object):
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        verb_excl_group = self.parser.add_mutually_exclusive_group()
        verb_excl_group.add_argument("-q", "--quiet", action="store_true")
        verb_excl_group.add_argument("-v", "--verbose", action="store_true")

        self.parser.add_argument('--verify-ssl', dest='verify_ssl',
                                 action='store_true')
        self.parser.add_argument('--no-verify-ssl', dest='verify_ssl',
                                 action='store_false')
        self.parser.add_argument('--api-version', metavar='VER', type=int)
        self.parser.add_argument('--username', metavar='USERNAME')
        self.parser.add_argument('--password', metavar='PASSWORD')

        auth_excl_group = self.parser.add_mutually_exclusive_group()
        auth_excl_group.add_argument(
            '--authorization-service-url', metavar='AUTH_SERVICE_URL', type=str,
            help=(
                'auth service host URL with with scheme and path '
                '[e.g. http://foo.com/v2/token] (v2 API only)'
            ),
        )
        # DEPRECATED old form of the argument that assumes a path for the URL
        auth_excl_group.add_argument(
            '--authorization-service', metavar='AUTH_SERVICE', type=str,
            help=(
                '[DEPRECATED] auth service host URL with scheme, without path '
                '[e.g. http://foo.com] (v2 API only)'
            ),
        )

        self.parser.add_argument(
            '--authorization-service-name', metavar='AUTH_SERVICE_NAME', type=str,
            help=(
                'auth service URL "service" query parameter for custom auth service names '
                '[e.g. container_registry, for GitLab auth] (v2 API only)'
            ),
        )

        self.parser.add_argument('registry', metavar='REGISTRY', nargs=1,
                                 help='registry URL (including scheme)')
        self.parser.add_argument('repository', metavar='REPOSITORY', nargs='?',
                                 help='repository (including namespace)')
        self.parser.add_argument('ref', metavar='REF', nargs='?',
                                 help='tag or digest')

        self.parser.set_defaults(verify_ssl=True, api_version=None)

    def run(self):
        args = self.parser.parse_args()

        basic_config_args = {}
        if args.verbose:
            basic_config_args['level'] = logging.DEBUG
        elif args.quiet:
            basic_config_args['level'] = logging.WARNING

        logging.basicConfig(**basic_config_args)

        kwargs = {
            'username': args.username,
            'password': args.password,
            'verify_ssl': args.verify_ssl,
            'auth_service_name': args.authorization_service_name,
            'auth_service_url_full': args.authorization_service_url
        }

        # Get the URL of the auth service from the command-line flags, accounting for the
        # deprecated url flag; only use the deprecated one if the
        if args.authorization_service:
            warnings.warn(
                'The --authorization-service flag is deprecated; '
                'use --authorization-service-url instead',
                DeprecationWarning
            )
            kwargs.setdefault('auth_service_url_full',
                              urljoin(args.authorization_service, 'v2/token'))

        if args.api_version:
            kwargs['api_version'] = args.api_version

        client = DockerRegistryClient(args.registry[0], **kwargs)

        if args.repository:
            if args.ref:
                self.show_manifest(client, args.repository, args.ref)
            else:
                self.show_tags(client, args.repository)
        else:
            self.show_repositories(client)

    def show_repositories(self, client):
        try:
            repositories = client.repositories()
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Catalog/Search not supported")
            else:
                raise
        else:
            print("Repositories:")
            for repository in repositories.keys():
                print("  - {0}".format(repository))

    def show_tags(self, client, repository):
        try:
            repo = client.repository(repository)
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Repository {0} not found".format(repository))
            else:
                raise
        else:
            print("Tags in repository {0}:".format(repository))
            for tag in repo.tags():
                print("  - {0}".format(tag))

    def show_manifest(self, client, repository, ref):
        try:
            repo = client.repository(repository)
        except requests.HTTPError as e:
            if e.response.status_code == requests.codes.not_found:
                print("Repository {0} not found".format(repository))
            else:
                raise
        else:
            assert client.api_version in [1, 2]
            if client.api_version == 2:
                manifest, digest = repo.manifest(ref)
                print("Digest: {0}".format(digest))
                print("Manifest:")
                print(json.dumps(manifest, indent=2, sort_keys=True))
            else:
                image = repo.image(ref)
                image_json = image.get_json()
                print("Image ID: {0}".format(image.image_id))
                print("Image JSON:")
                print(json.dumps(image_json, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        cli = CLI()
        cli.run()
    except KeyboardInterrupt:
        pass
