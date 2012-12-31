# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/


# This is all work in progress and just works barely to demo the Arduino
# HSM proof of concept. Don't expect magic here. It might evolve to a nice
# Python EC2 library at some later stage.


import base64
import time
import urllib
from xml.etree import ElementTree

import requests


class EC2RequestBuilder:

    EC2_API_ENDPOINT = "ec2.amazonaws.com"
    EC2_API_VERSION = "2012-12-01"

    def __init__(self, action, key, hsm, endpoint=EC2_API_ENDPOINT):
        self._path = "/"
        self._version = self.EC2_API_VERSION
        self._endpoint = endpoint
        self._action = action
        self._key = key
        self._hsm = hsm
        self._expires = 30
        self._parameters = {}

    def path(self, path):
        self._path = path

    def version(self, version):
        self._version = version

    def param(self, name, value):
        self._parameters[name] = value

    def expires(self, expires):
        self._expires = expires

    def _generate_timestamp(self, t):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

    def _hsm_sign_aws(self, msg):
        r = requests.post(self._hsm, data=msg)
        response = r.json()
        if not response.get('success'):
            raise Exception("Signing failed")
        return response['signature'].decode('hex')

    def _generate_signature(self, params):
        query_string = ""
        for name in sorted(params.keys()):
            if len(query_string) != 0:
                query_string += "&"
            query_string += "%s=%s" % (name, urllib.quote(params[name]))
        msg = "%s\n%s\n%s\n%s" % ("GET", self._endpoint, self._path, query_string)
        return base64.b64encode(self._hsm_sign_aws(msg))

    def build(self):
        request_params = {"Action": self._action, "Version": self._version, "AWSAccessKeyId": self._key,
                          "SignatureMethod": "HmacSHA1", "SignatureVersion": "2",
                          "Expires": self._generate_timestamp(time.time() + self._expires)}
        # Collect all the request parameters
        for name in self._parameters.keys():
            value = self._parameters[name]
            if isinstance(value, (list, tuple, set)):
                for idx, val in enumerate(value, 1):
                    request_params["%s.%d" % (name, idx)] = str(val)
            else:
                request_params[name] = str(value)
        # Generate the signature
        request_params["Signature"] = self._generate_signature(request_params)
        # Build the url
        return "https://%s%s?%s" % (self._endpoint, self._path, urllib.urlencode(request_params))

class Group:
    def __init__(self, tree):
        self.groupId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}groupId")

class InstanceState:
    def __init__(self,tree):
        self.code = int(tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}code"))
        self.name = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}name")

class Instance:
    def __init__(self,tree):
        self.instanceId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}instanceId")
        self.imageId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}imageId")
        self.dnsName = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}dnsName")
        self.privateDnsName = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}privateDnsName")
        self.instanceType = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}instanceType")
        self.keyName = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}keyName")
        self.instanceState = InstanceState(tree.find("{http://ec2.amazonaws.com/doc/2012-12-01/}instanceState"))

class Reservation:
    def __init__(self, tree):
        self.reservationId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}reservationId")
        self.ownerId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}ownerId")
        self.groups = []
        for e in tree.findall("{http://ec2.amazonaws.com/doc/2012-12-01/}groupSet/{{http://ec2.amazonaws.com/doc/2012-12-01/}}item"):
            self.groups.append(Group(e))
        self.instances = []
        for e in tree.findall("{http://ec2.amazonaws.com/doc/2012-12-01/}instancesSet/{http://ec2.amazonaws.com/doc/2012-12-01/}item"):
            self.instances.append(Instance(e))

class DescribeInstancesResponse:
    def __init__(self, tree):
        self.reservations = []
        for e in tree.findall("{http://ec2.amazonaws.com/doc/2012-12-01/}reservationSet/{http://ec2.amazonaws.com/doc/2012-12-01/}item"):
            self.reservations.append(Reservation(e))

class RunInstancesResponse:
    def __init__(self, tree):
        self.reservationId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}reservationId")
        self.ownerId = tree.findtext("{http://ec2.amazonaws.com/doc/2012-12-01/}ownerId")
        self.groups = []
        for e in tree.findall("{http://ec2.amazonaws.com/doc/2012-12-01/}groupSet/{{http://ec2.amazonaws.com/doc/2012-12-01/}}item"):
            self.groups.append(Group(e))
        self.instances = []
        for e in tree.findall("{http://ec2.amazonaws.com/doc/2012-12-01/}instancesSet/{http://ec2.amazonaws.com/doc/2012-12-01/}item"):
            self.instances.append(Instance(e))

EC2_RESPONSE_OBJECTS = {
    "{http://ec2.amazonaws.com/doc/2012-12-01/}DescribeInstancesResponse": DescribeInstancesResponse
}

class EC2Service:

    def __init__(self, key, hsm, endpoint=None):
        self._key = key
        self._hsm = hsm
        self._endpoint = endpoint

    def run_instances(self, image_id, min_count=1, max_count=None, key_name=None,
                      security_groups=[], user_data=None, instance_type=None, client_token=None):
        builder = EC2RequestBuilder("RunInstances", self._key, self._hsm)
        builder.param("ImageId", image_id)
        builder.param("MinCount", min_count)
        builder.param("MaxCount", max_count or min_count)
        if key_name:
            builder.param("KeyName", key_name)
        if security_groups:
            builder.param("SecurityGroups", security_groups)
        if user_data:
            builder.param("UserData", base64.b64encode(user_data))
        if instance_type:
            builder.param("InstanceType", instance_type)
        if client_token:
            builder.param("ClientToken", client_token)
        r = requests.get(builder.build())
        tree = ElementTree.fromstring(r.text)
        return r.status_code,EC2_RESPONSE_OBJECTS[tree.tag](tree)

    def describe_instances(self, instances=[], filters=[]):
        builder = EC2RequestBuilder("DescribeInstances", self._key, self._hsm)
        url = builder.build()
        r = requests.get(builder.build())
        tree = ElementTree.fromstring(r.text)
        return r.status_code,EC2_RESPONSE_OBJECTS[tree.tag](tree)
