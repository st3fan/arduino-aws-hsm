#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from aws import EC2Service


# CHANGE THIS TO YOUR KEY ID
AWS_ACCESS_KEY_ID="YOURAPIKEYID"

# CHANGE THIS TO POINT TO THE HSM
HSM_API_URL="http://127.0.0.1:8086/sign/aws"


if __name__ == "__main__":
    service = EC2Service(AWS_ACCESS_KEY_ID, HSM_API_URL)
    status,response = service.describe_instances()
    if status == 200:
        for reservation in response.reservations:
            for instance in reservation.instances:
                print reservation.reservationId, instance.instanceId, instance.instanceType,instance.instanceState.name
    else:
        print "Request failed with error",status
        print response

