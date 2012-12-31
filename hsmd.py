#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from bottle import request, route, run, template
import serial
import sys

def sign(port, data):
    port.write("SIGN-AWS-V2 " + data + "\x00")
    response = port.readline().strip()
    (status, data) = response.split()
    return (status, data)

@route('/sign/aws', method='POST')
def index():
    (status,data) = sign(ser, request.body.getvalue())
    if status == 'SUCCESS':
        return {"success":True, "signature":data}
    else:
        return {"success":False, "error": data}

if __name__ == "__main__":
    ser = serial.Serial(sys.argv[1], 115200)
    run(host='127.0.0.1', server='wsgiref', port=8086)
