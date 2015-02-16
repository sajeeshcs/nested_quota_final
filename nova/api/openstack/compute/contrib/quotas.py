# Copyright 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# import keystoneclient.middleware.auth_token as auth_token
import keystonemiddleware.auth_token as auth_token
import nova.context
import webob

from keystoneclient.v3 import client
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import db
from nova import exception
from nova.i18n import _
from nova import objects
from nova import quota
from nova import utils
from oslo.utils import strutils
import six.moves.urllib.parse as urlparse

KEYSTONE_CONF = auth_token.CONF

QUOTAS = quota.QUOTAS
NON_QUOTA_KEYS = ['tenant_id', 'id', 'force']

# Quotas that are only enabled by specific extensions
EXTENDED_QUOTAS = {'server_groups': 'os-server-group-quotas',
                   'server_group_members': 'os-server-group-quotas'}

authorize_root_update = extensions.\
                        extension_authorizer('compute',
                                             'quotas:root:update')
authorize_update = extensions.extension_authorizer('compute',
                                                   'quotas:update')
authorize_show = extensions.extension_authorizer('compute',
                                                 'quotas:show')
authorize_root_delete = extensions.\
                        extension_authorizer('compute',
                                             'quotas:root:delete')
authorize_delete = extensions.extension_authorizer('compute',
                                                   'quotas:delete')


class QuotaSetsController(wsgi.Controller):
    supported_quotas = []

    def __init__(self, ext_mgr):
        self.ext_mgr = ext_mgr
        self.supported_quotas = QUOTAS.resources
        for resource, extension in EXTENDED_QUOTAS.items():
            if not self.ext_mgr.is_loaded(extension):
                self.supported_quotas.remove(resource)

    def _format_quota_set(self, project_id, quota_set):
        """Convert the quota object to a result dict."""

        if project_id:
            result = dict(id=str(project_id))
        else:
            result = {}

        for resource in self.supported_quotas:
            if resource in quota_set:
                result[resource] = quota_set[resource]

        return dict(quota_set=result)

    def _validate_quota_limit(self, resource, limit, minimum, maximum):
        # NOTE: -1 is a flag value for unlimited
        if limit < -1:
            msg = (_("Quota limit %(limit)s for %(resource)s "
                     "must be -1 or greater.") %
                   {'limit': limit, 'resource': resource})
            raise webob.exc.HTTPBadRequest(explanation=msg)

        def conv_inf(value):
            return float("inf") if value == -1 else value

        if conv_inf(limit) < conv_inf(minimum):
            msg = (_("Quota limit %(limit)s for %(resource)s must "
                     "be greater than or equal to already used and "
                     "reserved %(minimum)s.") %
                   {'limit': limit, 'resource': resource, 'minimum': minimum})
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if conv_inf(limit) > conv_inf(maximum):
            msg = (_("Quota limit %(limit)s for %(resource)s must be "
                     "less than or equal to %(maximum)s.") %
                   {'limit': limit, 'resource': resource, 'maximum': maximum})
            raise webob.exc.HTTPBadRequest(explanation=msg)

    def _get_quotas(self, context, id, user_id=None, usages=False):
        if user_id:
            values = QUOTAS.get_user_quotas(context, id, user_id,
                                            usages=usages)
        else:
            values = QUOTAS.get_project_quotas(context, id, usages=usages)

        if usages:
            return values
        else:
            return {k: v['limit'] for k, v in values.items()}

    """ Function for finding the parent_id of a project.
        For root project ,parent_id is NULL"""

    def _get_parent_id(self, token, project_id):
        auth_host = KEYSTONE_CONF.keystone_authtoken.auth_host
        auth_port = int(KEYSTONE_CONF.keystone_authtoken.auth_port)
        auth_prcl = 'http'
        auth_url = '%s://%s:%s/%s' % (auth_prcl, auth_host, auth_port, "v3/")
        keystone = client.Client(token=token, auth_url=auth_url,
                                 project_id=project_id)
        try:
            data = keystone.projects.get(project_id).__dict__
        except Exception:
            raise webob.exc.HTTPForbidden()
        parent_id = None
        try:
            parent_id = data["parent_id"]
        except Exception:
            pass
        return parent_id

    def _get_immediate_child_list(self, token, parent_id):
        child_list = []
        auth_host = KEYSTONE_CONF.keystone_authtoken.auth_host
        auth_port = int(KEYSTONE_CONF.keystone_authtoken.auth_port)
        auth_prcl = 'http'
        auth_url = '%s://%s:%s/%s' % (auth_prcl, auth_host, auth_port, "v3/")
        keystone = client.Client(token=token, auth_url=auth_url,
                                 project_id=parent_id)
        try:
            data = keystone.projects.get(parent_id,
                                        subtree_as_list=True).__dict__
        except Exception:
            raise webob.exc.HTTPForbidden()
        subtree = []
        try:
            subtree = data["subtree"]
        except Exception:
            pass
        for item in subtree:
            project_info = item["project"]
            try:
                if project_info["parent_id"] == parent_id:
                    child_list.append(project_info["id"])
            except Exception:
                pass
        return child_list

    def _delete_project_quota(self, req, id, body):
        context = req.environ['nova.context']
        # id is made equivalent to project_id for better readability
        project_id = id
        child_list = []
        parent_id = None
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                parent_id = self._get_parent_id(token, project_id)
                target = {"project_id": parent_id}
                try:
                    if parent_id:
                        authorize_delete(context, target=target)
                        nova.context.\
                            authorize_root_or_parent_project_context(context,
                                                                     parent_id)
                    else:
                        authorize_root_delete(context)
                        nova.context.\
                            authorize_root_or_parent_project_context(context,
                                                                    project_id)
                except exception.Forbidden:
                    raise webob.exc.HTTPForbidden()

                if parent_id:
                    child_list =\
                        self._get_immediate_child_list(token, parent_id)
                else:
                    child_list =\
                        self._get_immediate_child_list(token, project_id)

        if parent_id is not None:
            if id not in child_list:
                raise exception.InvalidParent(parent_id=parent_id,
                                              project_id=project_id)
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]

        quota_set = body['quota_set']
        force_update = strutils.bool_from_string(quota_set.get('force',
                                                               'False'))

        try:
            settable_quotas = QUOTAS.get_settable_quotas(context,
                                                         project_id,
                                                         parent_id,
                                                         user_id=user_id)
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()
        for key, value in body['quota_set'].iteritems():
            if key == 'force' or (not value and value != 0):
                continue
            # validate whether already used and reserved exceeds the new
            # quota, this check will be ignored if admin want to force
            # update
            value = utils.validate_integer(value, key)
            if not force_update:
                minimum = settable_quotas[key]['minimum']
                maximum = settable_quotas[key]['maximum']
                self._validate_quota_limit(key, value, minimum, maximum)
            try:
                objects.Quotas.create_limit(context, project_id,
                                            key, value, user_id=user_id)
            except exception.QuotaExists:
                objects.Quotas.update_limit(context, project_id,
                                            key, value, user_id=user_id)
            except exception.AdminRequired:
                raise webob.exc.HTTPForbidden()

            if parent_id:
                db.quota_allocated_update(context, parent_id, child_list)

    def show(self, req, id):
        context = req.environ['nova.context']
        """ id is made equivalent to project_id for better readability"""
        project_id = id
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        parent_id = None
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                parent_id = self._get_parent_id(token, project_id)
        try:
            if user_id:
                authorize_show(context)
                nova.context.authorize_project_context(context, project_id)
            else:
                if parent_id:
                    if context.project_id == parent_id:
                        target = {"project_id": parent_id}
                        authorize_show(context, target)
                        nova.context.authorize_project_context(context,
                                                               parent_id)
                    else:
                        target = {"project_id": project_id}
                        authorize_show(context, target)
                        nova.context.authorize_project_context(context,
                                                               project_id)
                else:
                    nova.context.authorize_project_context(context,
                                                           project_id)
            return self._format_quota_set(id,
                    self._get_quotas(context, id, user_id=user_id))
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()

    def update(self, req, id, body):
        context = req.environ['nova.context']
        # id is made equivalent to project_id for better readability
        project_id = id
        child_list = []
        parent_id = None
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        if hasattr(context, 'auth_token') and hasattr(context, 'project_id'):
            if(context.auth_token and context.project_id):
                token = context.auth_token
                parent_id = self._get_parent_id(token, project_id)
                target = {"project_id": parent_id}
                try:
                    if user_id:
                        authorize_update(context)
                        nova.context.authorize_project_context(context,
                                                               project_id)
                    else:
                        if parent_id:
                            authorize_update(context, target=target)
                            nova.context.\
                            authorize_root_or_parent_project_context(context,
                                                                     parent_id)
                        else:
                            authorize_root_update(context)
                            nova.context.\
                            authorize_root_or_parent_project_context(context,
                                                                  project_id)
                except exception.Forbidden:
                    raise webob.exc.HTTPForbidden()

                if parent_id:
                    child_list =\
                        self._get_immediate_child_list(token, parent_id)
                else:
                    child_list =\
                        self._get_immediate_child_list(token, project_id)

        if parent_id is not None:
            if id not in child_list:
                raise exception.\
                    InvalidParent(parent_id=parent_id, project_id=project_id)

        ################

        quota_set = body['quota_set']
        force_update = strutils.bool_from_string(quota_set.get('force',
                                                               'False'))

        try:
            settable_quotas = QUOTAS.\
                              get_settable_quotas(context, project_id,
                                                 parent_id, user_id=user_id)
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()

        for key, value in body['quota_set'].iteritems():
            if key == 'force' or (not value and value != 0):
                continue
            # validate whether already used and reserved exceeds the new
            # quota, this check will be ignored if admin want to force
            # update
            value = utils.validate_integer(value, key)
            if not force_update:
                minimum = settable_quotas[key]['minimum']
                maximum = settable_quotas[key]['maximum']
                self._validate_quota_limit(key, value, minimum, maximum)
            try:
                objects.Quotas.create_limit(context, project_id,
                                      key, value, user_id=user_id)
            except exception.QuotaExists:
                objects.Quotas.update_limit(context, project_id,
                                      key, value, user_id=user_id)
            if parent_id:
                db.quota_allocated_update(context, parent_id, child_list)

        return self._format_quota_set(id, self._get_quotas(context, id,
                                                           user_id=user_id))

    def defaults(self, req, id):
        context = req.environ['nova.context']
        authorize_show(context)
        values = QUOTAS.get_defaults(context)
        return self._format_quota_set(id, values)

    def delete(self, req, id):
        context = req.environ['nova.context']
        params = urlparse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        body = {"quota_set": {"instances": "0",
                              "cores": "0",
                              "ram": "0",
                              "floating_ips": "0",
                              "fixed_ips": "0",
                              "metadata_items": "0",
                              "injected_files": "0",
                              "injected_file_content_bytes": "0",
                              "injected_file_path_bytes": "0",
                              "security_groups": "0",
                              "security_group_rules": "0",
                              "server_groups": "0",
                              "server_group_members": "0",
                              "key_pairs": "0"}}
        try:
            if user_id:
                authorize_delete(context)
                nova.context.authorize_project_context(context, id)
                QUOTAS.destroy_all_by_project_and_user(context,
                                                       id, user_id)
            else:
                self._delete_project_quota(req, id, body)
        except exception.Forbidden:
            raise webob.exc.HTTPForbidden()


class Quotas(extensions.ExtensionDescriptor):
    """Quotas management support."""

    name = "Quotas"
    alias = "os-quota-sets"
    namespace = "http://docs.openstack.org/compute/ext/quotas-sets/api/v1.1"
    updated = "2011-08-08T00:00:00Z"

    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension('os-quota-sets',
                                            QuotaSetsController(self.ext_mgr),
                                            member_actions={'defaults': 'GET'})
        resources.append(res)

        return resources
