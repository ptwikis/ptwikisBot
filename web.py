#!/usr/bin/python
# -*- coding: utf-8 -*-

import json, socket

def app(environ, start_response):
    if environ['REQUEST_METHOD'] == 'POST' and environ.get('CONTENT_TYPE') == 'application/json':
        return github(environ, start_response)
    elif environ['REQUEST_METHOD'] == 'POST':
        return post(environ, start_response)
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [u'Página do ptwikisBot em Construção'.encode('latin1')]

def post(environ, start_response):
    print 'post'
    start_response('200 OK', [('Content-Type', 'text/html')])
    return ['POST method only authorized for GitHub IP range']

def ip2bin(ip):
    octets = map(int, ip.split('/')[0].split('.'))
    binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
    range = int(ip.split('/')[1]) if '/' in ip else None
    return binary[:range] if range else binary

def github(environ, start_response):
    ip = environ.get('REMOTE_ADDR', '0.0.0.0')
    if ip2bin(ip).startswith(ip2bin('192.30.252.0/22')):
        print 'GitHub IP'
    else:
        print 'Not GitHub IP: ' + ip
    size = int(environ.get('CONTENT_LENGTH', 0))
    data = json.loads(environ.get('wsgi.input').read(size))
    for c in data['commits']:
        msg = u'\x0fGitHub [\x0306%s\x03] \x0303%s\x03 (%s) \x0314commit\x03 \x0312%s\x03 (%s)' % (data['repository']['full_name'], c['author']['name'],
            c['author']['username'], c['url'], c['message'][:100])
        irc('#wikipedia-pt-tecn ' + msg.encode('utf-8'))

    start_response('200 OK', [('Content-Type', 'text/html')])
    return ['github OK']

def irc(msg):
    with open('/data/project/ptwikis/bot/bothost') as f:
        host = f.read().split(':')
    s = socket.socket()
    s.connect((host[0], int(host[1])))
    s.send(msg)
    s.shutdown(socket.SHUT_RDWR)

if __name__ == '__main__':
    from flup.server.fcgi import WSGIServer
    WSGIServer(app).run()
