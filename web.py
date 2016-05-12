#!/usr/bin/python
# -*- coding: utf-8 -*-

import json, socket, sys

html = u'''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
        <meta http-equiv="content-type" content="text/html; charset=utf-8" />
        <title>Banco de dados do ptwikisBot</title>
        <link rel="icon" type="image/x-icon" href="static/Tool_labs_logo.ico" />
        <link rel="stylesheet" type="text/css" media="screen" href="static/style.css" />
    </head>
    <body>
        <div id="content-wrapper">
            <div id="menu">
<img src="//upload.wikimedia.org/wikipedia/commons/thumb/a/a4/Tool_labs_logo.svg/120px-Tool_labs_logo.svg.png">
                <div id="menu-content">
<div id="menu-item"><a href="https://github.com/ptwikis/ptwikisBot/wiki">Manual</a></div>
<div id="menu-item"><a href="https://webchat.freenode.net/?channels=wikipedia-pt">Web chat</a></div>
                </div>
            </div>
            <div id="content">
<br/>
<h1>Banco de dados do ptwikisBot</h1>
<hr/> Tool Labs – Ferramentas para projetos lusófonos <br/><br/>
%s
            </div>
       </div>
       <div style="text-align:center; font-size:x-small; margin: 10px 10px 12px 181px">
O <a href="https://github.com/ptwikis/ptwikisBot">código-fonte</a> do robô é disponibilizado sob a licença GNU General Public License 3.0 (GPL V3).
       </div>
    </body>
</html>
'''

def page():
  with open('db.json') as f:
    db = json.load(f)
  channels = u'<h2>Configuração dos canais</h2><hr/>\n'
  for chan in sorted(set(db['vigiar'].keys() + db['links'])):
    channels += u'<h3>%s</h3>\n<p>Wikilinks: %sligado</p>\n' % (chan, u'' if chan in db['links'] else u'des')
    if chan in db['vigiar']:
      pages = u'\n'.join(u'<tr><td>%s</td></tr>' % p for p in db['vigiar'][chan])
      channels += u'<table class="wikitable"><tr><th>Páginas vigiadas</th></tr>\n%s\n</table>\n\n' % pages
  phab = u'''<h2>Phabricator</h2><hr/>
<p>Os seguintes termos disparam notificações do phabricator e gerrit em #wikipedia-pt-tecn:</p>
<ul>
%s
</ul>
''' % u'\n'.join(u'<li>%s' % t for t in sorted(db['phab']))
  return html % (channels + u'<br/>\n' + phab)

def app(environ, start_response):
  if environ['REQUEST_METHOD'] == 'POST':
    ip = environ.get('REMOTE_ADDR', '0.0.0.0')
    if environ.get('CONTENT_TYPE') == 'application/json' and ip2bin(ip).startswith(ip2bin('192.30.252.0/22')):
      return github(environ, start_response)
    else:
      return post(environ, start_response)
  start_response('200 OK', [('Content-Type', 'text/html')])
  return [page().encode('utf-8')]

def post(environ, start_response):
  print >> sys.stderr, 'ptwikisBot-web: Not GitHub IP: ' + environ.get('REMOTE_ADDR', '0.0.0.0')
  start_response('200 OK', [('Content-Type', 'text/html')])
  return ['POST method only authorized for GitHub IP range']

def ip2bin(ip):
  octets = map(int, ip.split('/')[0].split('.'))
  binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
  range = int(ip.split('/')[1]) if '/' in ip else None
  return binary[:range] if range else binary

def github(environ, start_response):
  size = int(environ.get('CONTENT_LENGTH', 0))
  data = json.loads(environ.get('wsgi.input').read(size))
  for c in data['commits']:
    msg = u'\x0fGitHub [\x0306%s\x03] \x0303%s\x03 (%s) \x0314commit\x03 \x0312%s\x03 (%s)' % \
      (data['repository']['full_name'], c['author']['name'], c['author']['username'], c['url'], c['message'][:100])
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
