#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Script auxiliar do ptwikisBot.

As funções deste script podem ser alteradas e recarregadas sem
a necessidade de reiniciar o robô, apenas usando o comando !reload
em algum canal que o ptwikisBot esteja.

@autor:   [[Usuário:Danilo.mac]]
@licença: GNU General Public License 3.0 (GPL V3)
"""

import time, re, oursql, os, socket, json
from urllib import urlopen
from collections import deque

reLink = re.compile(ur'\[\[:?([^]|:][^][|]*)\]\]')
reTemplate = re.compile(ur'\{\{([^{}|]+)\}\}')

channels = {'#wikipedia-pt': u'w',
            '#wikipedia-pt-bots': u'w',
            '#wikipedia-pt-tecn': u'w',
            '#wikipedia-pt-social': u'w',
            '#wikipedia-pt-ajuda': u'w',
            '#wikipedia-pt-ops': u'w',
            '#wikimedia-br': u'wmbr',
            '#wiktionary-pt': u'wikt',
            '#wikibooks-pt': u'b',
            '#wikivoyage-pt': u'voyage',
            '#wikiversity-pt': u'v',
            '#wikisource-pt': u's',
            '#wikiquote-pt': u'q',
            '#wikinews-pt': u'n'}

prefixes = {u'w': u'https://pt.wikipedia.org/wiki/',
            u'wp': u'https://pt.wikipedia.org/wiki/Wikipédia:',
            u'v': u'https://pt.wikiversity.org/wiki/',
            u'b': u'https://pt.wikibooks.org/wiki/',
            u's': u'https://pt.wikisource.org/wiki/',
            u'q': u'https://pt.wikiquote.org/wiki/',
            u'n': u'https://pt.wikinews.org/wiki/',
            u'wikt': u'https://pt.wiktionary.org/wiki/',
            u'voyage': u'https://pt.wikivoyage.org/wiki/',
            u'wmbr': u'https://br.wikimedia.org/wiki/',
            u'mw': u'https://www.mediawiki.org/wiki/',
            u'commons': u'https://commons.wikimedia.org/wiki/',
            u'meta': u'https://meta.wikimedia.org/wiki/',
            u'bugzilla': u'https://bugzilla.wikimedia.org/show_bug.cgi?id=',
            u'gerrit': u'https://gerrit.wikimedia.org/r/',
            u'phabricator': u'https://phabricator.wikimedia.org/',
            u'testwiki': u'https://test.wikipedia.org/wiki/'}

dbs = {u'w': 'ptwiki',
       u'v': 'ptwikiversity',
       u'b': 'ptwikibooks',
       u's': 'ptwikisource',
       u'q': 'ptwikiquote',
       u'n': 'ptwikinews',
       u'wikt': 'ptwiktionary',
       u'voyage': 'ptwikivoyage',
       u'wmbr': 'brwikimedia',
       u'commons': 'commonswiki',
       u'meta': 'metawiki'}

feedChan = ['#mediawiki-feed']

RCFlags = set(['esplanada'])
users = {}

def wmbot(channel, message):
  """
  Manda o wm-bot falar
  """
  if not isinstance(channel, str) or channel not in channels or not isinstance(message, basestring):
    print 'Erro em wmbot({!r}, {!r})'.format(channel, message)
    return
  if isinstance(message, unicode):
    message = message.encode('utf-8')
  s = socket.socket()
  s.connect(('wm-bot.eqiad.wmflabs', 64834))
  s.send(channel + ' ' + message)
  s.shutdown(socket.SHUT_RDWR)

def sql(db, query, params=tuple()):
  """
  Consulta o banco de dados
  """
  if db[0] == '#':
    db = db in channels and channels[db] in dbs and dbs[channels[db]] or 'ptwiki'
  try:
    c = conn(db)
    c.execute(query, params)
  except oursql.OperationalError:
    try:
      c = conn(db)
      c.execute(query, params)
    except Exception as e:
      print repr(e)
      return False
  return c.fetchall()

def conn(db, host=None):
  """
  Conecta ao banco de dados  
  """
  if host:
    connection = oursql.connect(db=db, host=host, read_default_file=os.path.expanduser('~/replica.my.cnf'), read_timeout=10, charset='utf8', use_unicode=True, autoreconnect=True, autoping=True)
  else:
    connection = oursql.connect(db=db + '_p', host=db + '.labsdb', read_default_file=os.path.expanduser('~/replica.my.cnf'), read_timeout=10, charset='utf8', use_unicode=True, autoreconnect=True, autoping=True)
  return connection.cursor()

def testcmd(msg):
  """
  Verifica se a mensagem inicia com o prefíxo de comando
  """
  for prefix in (u'!'):
    if msg.startswith(prefix):
      return msg[len(prefix):].strip()
  return False

def cmd(args, channel, user, cloak):
  """
  Recebe comandos e devolve uma respota ao mesmo canal,
  essa função roda em uma thread separada para que processos
  longos não interrompam outras funções do robô
  """
  # Links
  if args == u'link':
     return u'Wikilinks ligado' if db.append('links', channel) else u'Já está ligado'
  elif args == u'sem link':
    return u'Wikilinks desligado' if db.remove('links', channel) else u'Já está desligado'

  # Avisos
  elif args == u'avisos' and channel == '#wikipedia-pt-bots':
    if log.avisos:
      return u'Os avisos já estão ligdos, para desligar use !sem avisos'
    else:
      log.avisos.add(user)
      if RCFlags:
        RCFlags.clear()
      return log.avisos and u'Avisos AntiVandalismo ligados'
  elif args == u'sem avisos' and channel == '#wikipedia-pt-bots':
    if not log.avisos:
      return u'Os avisos já estão desligados, para ligar use !avisos'
    else:
      log.avisos.clear()
      return u'Avisos AntiVandalismo desligados'

  # Número de afluentes
  elif args[0:10] == u'afluentes ':
    r = sql(dbs[channel in channels and channels[channel] or 'w'], "SELECT COUNT(*) FROM pagelinks WHERE pl_namespace = 0 AND pl_title = ?", (args[10:].replace(u' ', u'_'),))
    return r and u'A página {}contém {} afluentes'.format(not r[0][0] and u'não existe ou ' or u'', r[0][0]) or u'Ocorreu um erro durante a consulta'

  # Wm-bot
  elif args.startswith(u'wm-bot ') and cloak:
    msg = args[7:].split(' ', 1)
    if len(msg) == 2 and msg[0] in channels and msg[1]:
      wmbot(msg[0].encode('utf-8'), msg[1].encode('utf-8'))
    elif msg[0] not in channels:
      wmbot(channel, u' '.join(msg))

  # Mudanças recentes
  elif args == 'mr' and channel == '#wikipedia-pt-bots' and cloak:
    if RCFlags:
      RCFlags.clear()
      return u'Mudanças recentes desligadas'
    else:
      return u'Para ligar as mudanças recentes use uma flag (!mr <flag>): {} ou registro[/tipo]'.format(u', '.join(flags))
  elif args[0:3] == 'mr ' and channel == '#wikipedia-pt-bots' and cloak:
    if u'w:' in args:
      RCFlags.add(args[args.index(u'w:'):].replace(u'_', u' '))
    else:
      for flag in re.findall(ur'\bregistro/\w+', args):
        RCFlags.add(flag)
      for flag in flags:
        if flag in args:
          RCFlags.add(flag)
    return RCFlags and u'Serão exibidos: {}, use o comando !mr para parar'.format(listar(RCFlags)) or \
      u'Nenhuma flag reconhecida, flags disponíveis: {} ou registro[/tipo]'.format(u', '.join(flags))

  # Conhecidos que não precisam de mensagem de boas-vindas
  elif args.startswith(u'conhecido'):
    return db.parse('conhecidos', args[9:], u'o nick')

  # Usuários que acionam os avisos AntiVandalismo quando entram
  elif args.startswith(u'avisos'):
    return db.parse('AVusers', args[6:], u'o cloak')

  # Termos no feed do Phabricator que geram notificação
  elif args.startswith(u'phab'):
    return db.parse('phab', args[4:])


  # Outros
  elif args == 'reload log' and cloak:
    try:
      log.__class__ = Log
      log.reload()
    except Exception as e:
      return 'Erro: ' + repr(e)
    return u'log recarregado'
  elif args == 'stats' and cloak:
    return u'avisos: {}, mr: {}, monitorados pelos avisos: {} ({} bloqueados, {} revertidos, {} dispararam filtros)'.format(log.avisos and u'ligado' or u'desligado',
      listar(RCFlags) or u'desligado', len(log.users), *map(sum, zip(*((u['blocks'] and 1 or 0, u['rev'] and 1 or 0, u['filter'] and 1 or 0) for u in log.users.itervalues()))))
  elif args[0:4] == u'raw ' and cloak in ('wikipedia/danilomac', 'wikimedia/Sir-Lestaty-de-Lioncourt'): # restrito por segurança
    return '/raw ' + args[4:]
  elif args[0:5] == u'eval ' and cloak == 'wikipedia/danilomac': # para testes, restrito por segurança
    try:
      resp = repr(eval(args[5:]))
    except Exception as e:
      resp = repr(e)
    return resp
  elif args == u'limpar pontuação' and cloak:
    c = conn('p50380g50592__pt', 's2.labsdb')
    c.execute(u"TRUNCATE edições")
    return u'A tabela foi limpa'

reOla = re.compile(u'(?i)^(olá|oi|hola|hi|hello),? (ptwikisbot|robôs|wm-bot\d?)')

def noCmd(msg, channel, user):
  """
  Funções para menssagens que não começam com "!" ou "ptwikisBot:",
  essas funções não são processadas em thread separada como na
  função cmd, evite incluir processos demorados.
  """
  # Ignora mensagens que começam ou terminam com "-"
  if u'-' in (msg[0], msg[-1]):
    return

  # Wikilinks
  elif (u'[[' in msg or u'{{' in msg) and channel in db['links']:
    links = [parseLink(l, channel) for l in reLink.findall(msg)]
    links += [parseLink(l, channel, True) for l in reTemplate.findall(msg)]
    resp = links and ' '.join(links) or None
    return resp

  # Responde olá/oi/hi/hello/hola
  elif reOla.match(msg):
    ola = reOla.match(msg)
    if ola.group(2).lower()[0:6] in (u'wm-bot', u'robôs'): # manda o wm-bot responder também
      wmbot(channel, ola.group(1).encode('utf-8') + ' ' + user.split('!')[0])
    return ola.group(2).lower() in (u'ptwikisbot', u'robôs') and ola.group(1).encode('utf-8') + ' ' + user.split('!')[0]

class Log(object):
  """
  Classe para banco de dados temporário dos avisos antivandalismo.

  Os registros se perdem quando o robô desconecta mas não quando
  as funções são recarregadas.
  """
  def __init__(self):
    self.loading = False
    self.avisos = set()
    self.vigiar = set()
    self.queue = deque()
    self.AVFilters = {'7', '16', '18', '19', '56', '68', '70', '109', '120'}
    self.users = {}
    # lista cujos itens são ( u'usuário bloqueado nos últimos 6 meses', int(nº de bloqueios nesse período) )
    blocks = [(i[0].decode('utf-8'), int(i[1])) for i in sql('ptwiki', u"""SELECT
 log_title,
 COUNT(*)
 FROM logging
 WHERE log_type = 'block' AND log_action = 'block' AND log_timestamp > DATE_SUB(NOW(), INTERVAL 6 MONTH)
 GROUP BY log_title""")]
    self.groups = set(u[0].decode('utf-8') for u in sql('ptwiki', u"""SELECT user_name FROM user_groups INNER JOIN user ON ug_user = user_id GROUP BY ug_user"""))
    self.users = dict((user, {'blocks': n, 'rev': {}, 'filter': {}}) for user, n in blocks if user not in self.groups)
    self.bots = set(u[0].decode('utf-8') for u in sql('ptwiki', u"""SELECT user_name FROM user_groups INNER JOIN user ON ug_user = user_id WHERE ug_group = 'bot'"""))

  def reload(self):
    pass

  def logRev(self, user, page):
    """
    Recebe reversões
    """
    if not user or user in self.groups: # ignora usuários com grupos
      return
    if user in self.users:
      self.users[user]['rev'][page] = page in self.users[user]['rev'] and self.users[user]['rev'][page] + 1 or 1
    else:
      self.users[user] = {'blocks': 0, 'rev': {page: 1}, 'filter': {}}

  def logFilter(self, user, num):
    """
    Recebe registros de filtros
    """
    if not user or user in self.groups or num not in self.AVFilters: # ignora usuários com grupos e filtros que não estejam na lista
      return
    if user in self.users:
      self.users[user]['filter'][num] = num in self.users[user]['filter'] and self.users[user]['filter'][num] + 1 or 1
    else:
      self.users[user] = {'blocks': 0, 'rev': {}, 'filter': {num: 1}}
    return True

  def logBlock(self, user):
    """
    Recebe registros de bloqueio
    """
    if not user or user in self.groups: # ignora usuários com grupos
      return
    if user in self.users:
      self.users[user]['blocks'] += 1
    else:
      self.users[user] = {'blocks': 1, 'rev': {}, 'filter': {}}
      self.cleanLog() # Aproveita o registro de bloqueio para acionar a limpesa do log

  def cleanLog(self):
    """
    Mantém apenas os últimos 1000 usuários registros no log
    e usuários bloqueados
    """
    while len(self.queue) > 1000:
      user = self.queue.pop()
      if user in self.users and not self.users[user]['blocks']:
        del self.users[user]

#*******************
# Mudanças recentes
#*******************
reFilter = re.compile(ur'Filtro de abusos/(\d+)\|filtro \1\]\].*?\[\[([^]]+)\]\].*?Ações realizadas: (.+?)(?:$| \()')
reIp = re.compile(ur'^\d+\.\d+\.\d+\.\d+$|:[0-9A-Fa-f]{4}:')
reUrl = re.compile(ur'http://(.*?)&oldid=.*')
reRevUser = re.compile(ur'pecial:Contrib.+?/(.+?)\|')
revComments = {u'Foram [[WP:REV|revertid',
               u'Reversão de uma ou mais',
               u'bot: revertidas edições'}
flags = ('ips', 'sem grupo', 'com grupo', 'bot', 'filtro', 'rev', 'suspeitos', 'esplanada')

esplanadas = (u'Wikipédia:Esplanada/propostas/',
              u'Wikipédia:Esplanada/geral/',
              u'Wikipédia:Esplanada/anúncios',
              u'Wikipédia:Café',
              u'Wikipédia:Coordenação robótica')

def RC(msg):
  """
  Processa o feed do canal pt.wikipedia do irc.wikimedia.org

  As menssagens estão no formato:
  msg = [u'página', u'indicadores', u'url', u'usuário', u'(±dif)', u'sumário']

  Quando a função retorna uma tupla ('canal', u'menssagem') a menssagem é
  enviada ao canal.
  """
  if msg[0][0:9] == u'Especial:':

    # Filtro de abusos
    if msg[0] == u'Especial:Log/abusefilter':
      f = reFilter.search(msg[5])
      if f and f.group(1) in log.AVFilters:
        show = log.logFilter(msg[3], f.group(1))
      else:
        show = False
      if f and (show and log.avisos or 'filtro' in RCFlags and u'Ações realizadas: Não autorizar' in msg[5] or 'registro/abusefilter' in RCFlags):
        return '#wikipedia-pt-bots', u'{0} \x0311disparou filtro {1}\x0315 ({2}) em \x03[[{3}]]\x0315 https://pt.wikipedia.org/wiki/Especial:Registro_de_abusos?wpSearchUser={4}'.format(msg[3], f.group(1), f.group(3).lower(), f.group(2), msg[3].replace(u' ', u'_'))

    # Bloqueios
    elif msg[0] == u'Especial:Log/block' and msg[1] == u'block' and log.avisos:
      resp = re.search(ur'bloqueou "\[\[Usuári[ao](?:\(a\))?:([^]]+)\]\]".*?: ?(.*)', msg[5])
      log.logBlock(resp and resp.group(1))
      resp = resp and u'{} \x034foi bloqueado\x03 por {} ({})'.format(resp.group(1), msg[3], resp.group(2))
      return '#wikipedia-pt-bots', resp or u'erro no parser de bloqueio: ' + msg[5]

    # Direitos de usuário
    elif msg[0] == u'Especial:Log/rights':
      grupos = re.search(ur'alterou grupo de acesso para Usuári[ao](?:\(a\))?:([^:]+): de (.*?) para (.*?)(?:: ?(.*)|$)', msg[5])
      if not grupos:
        return '#wikipedia-pt-bots', u'erro no parser de alteração de direitos: {!r}'.format(msg[5])
      grupos = (grupos.group(1), set(grupos.group(2).split(', ')), set(grupos.group(3).split(', ')), grupos.group(4))
      grupos = (grupos[0], [u'-' + g for g in grupos[1] - grupos[2] - {'(nenhum)'}], [u'+' + g for g in grupos[2] - grupos[1] - {'(nenhum)'}], grupos[3])
      return '#wikipedia-pt-bots', u'{} teve seus direitos alterados por {}: {} ({})'.format(grupos[0],
        msg[3], u', '.join(grupos[1] + grupos[2]), grupos[3])

    # Outros registros
    elif RCFlags and ('registro' in RCFlags or 'registro/' + msg[0][13:] in RCFlags):
      return '#wikipedia-pt-bots', u', '.join(m for m in msg if m)

  else:
    rev = False

    # Registra reverções
    if msg[5][0:23] in revComments:
      rev = reRevUser.search(msg[5])
      rev = rev and rev.group(1)
      log.logRev(rev, msg[0])

    # Edições de usuários suspeitos (blacklist)
    if ('suspeitos' in RCFlags or log.avisos) and msg[3] in log.users:
      user = log.users[msg[3]]
      comment = msg[5] and (len(msg[5]) > 100 and msg[5][0:100] + u'...' or msg[5])
      blocks = user['blocks'] and u'\x0304{} bloqueio{}\x03'.format(user['blocks'], user['blocks'] > 1 and u's' or u'')
      revs = user['rev'] and (msg[0] in user['rev'] and u'\x0313{} revers{} na mesma página\x03'.format(user['rev'][msg[0]], user['rev'][msg[0]] > 1 and u'ões' or u'ão') or
        u'\x0313{0} revers{1} em outra{2} página{2}\x03'.format(*(lambda n:(n, n > 1 and u'ões' or u'ão', n > 1 and u's' or u''))(sum(user['rev'].values()))))
      filters = user['filter'] and u'\x0311disparou filtro{} {}\x03'.format(len(user['filter']) > 1 and u's' or u'',
        u', '.join(n > 1 and u'{}({}x)'.format(f, n) or f for f, n in user['filter'].items()))
      return '#wikipedia-pt-bots', u'{} \x0315({}\x0315) {} \x03[[{}]] \x0314{}\x0315 {}{}'.format(msg[3], u', '.join(tag for tag in (blocks, revs, filters) if tag),
        u'N' in msg[1] and u'\x037criou\x0315' or u'editou', msg[0], msg[4], reUrl.sub(ur'https://\1', msg[2]), comment and u'\x03 (' + comment + u')' or u'')

    # Edições por grupo de usuário
    elif RCFlags and RCFlags & {'ips', 'sem grupo', 'com grupo', 'bot'} or log.avisos:
      ip = reIp.search(msg[3])
      comment = msg[5] and (len(msg[5]) > 100 and msg[5][0:100] + u'...' or msg[5])
      user = ('ips' in RCFlags or log.avisos) and ip and u'03IP\x03 ' or \
         not ip and ('sem grupo' in RCFlags and msg[3] not in log.groups and u'11' or
        'com grupo' in RCFlags and msg[3] in log.groups and msg[3] not in log.bots and u'07' or
        'bot' in RCFlags and msg[3] in log.bots and u'14')
      if user:
        return '#wikipedia-pt-bots', u'\x03{}{}\x0315 {}\x03 {} \x0314{} \x0315{}{}'.format(user, msg[3], u'N' in msg[1] and u'criou' or u'editou', msg[0], msg[4],
          reUrl.sub(ur'https://\1', msg[2]), comment and u'\x03 (' + comment + u')' or u'')

    # Edições revertidas
    if rev and 'rev' in RCFlags:
      resp = u'{} \x0313foi revertido\x03 por {} em [[{}]]'.format(rev, msg[3], msg[0])
      return '#wikipedia-pt-bots', resp or u'Erro em aviso de reversão'

    # Esplanada
    elif RCFlags and 'esplanada' in RCFlags and msg[0].startswith(esplanadas):
      comment = msg[5] and (len(msg[5]) > 100 and msg[5][0:100] + u'...' or msg[5])
      return '#wikipedia-pt-bots', u'\x0303{}\x0315 {}\x0302 {} \x0314{} \x0315{}{}'.format(msg[3], u'N' in msg[1] and u'criou' or u'editou',
        msg[0], msg[4], reUrl.sub(ur'https://\1', msg[2]), comment and u'\x03 (' + comment + u')' or u'')

    # Páginas
    elif RCFlags and [1 for p in RCFlags if p.startswith('w:') and (p.endswith('%') and msg[0].startswith(p[2:-1]) or msg[0] == p[2:])]:
      comment = msg[5] and (len(msg[5]) > 100 and msg[5][0:100] + u'...' or msg[5])
      return '#wikipedia-pt-bots', u'{}\x0315 {}\x03 {} \x0314{} \x0315{}{}'.format(msg[3], u'N' in msg[1] and u'criou' or u'editou',
        msg[0], msg[4], reUrl.sub(ur'https://\1', msg[2]), comment and u'\x03 (' + comment + u')' or u'')

#***** fim da mudanças recentes *****

def listar(itens):
  """
  Tranforma uma sequencia ['a', 'b', 'c'] em 'a, b e c'
  """
  lista = ''
  n = len(itens) > 1 and len(itens) - 1 or 1
  for i, item in enumerate(itens):
    lista += (i == n and ' e ' or i > 0 and ', ' or '') + item
  return lista

def whoreplay(user, flag, cloak):
  """
  Registra quen está no canal
  """
  users[user] = [flag, cloak]

def join(user, channel, cloak):
  """
  Usuário entrou
  """
  if user.split('!')[0] == 'ptwikisBot' or channel in feedChan:
    return
  now = int(time.time())
  userhost = user[user.find('@') + 1:]
  if not 'users' in db:
    db['users'] = dbDict()
  if userhost in db['users'] and db['users'][userhost] > now:
    newJoin = False # usuário já tinha entrado nas últimas 16 horas
  else:
    for u, t in db['users'].items():
      if t < now:
        del db['users'][u]
    db['users'][userhost] = now + 57600
    newJoin = True # usuário não entrou nas últimas 16 horas

  if channel == '#wikipedia-pt-bots' and cloak:
    # Registra que usuário com cloak está no canal
    users[user.split('!')[0]] = ['', cloak]

    # Liga os avisos AntiVandalismo quando determinados usuários entram
    if cloak in db['AVusers']:
      ligar = not log.avisos
      log.avisos.add(user.split('!')[0])
      if ligar:
        return channel, (u'Avisos AntiVandalismo ligados')

  # Boas vindas no canal #wikipedia-pt-ajuda
  elif channel == '#wikipedia-pt-ajuda' and not cloak and user.split('!')[0].strip('_') not in db['conhecidos']:
    return channel, u'Olá {}. Bem-vindo ao canal de ajuda da Wikipédia em português. Se quiser fazer alguma consulta, escreva e espere até que possamos te responder.'.format(user.split('!')[0])

def modeChanged(user, channel, mode):
  """
  Usuário teve flag alterada
  """
  if channel == '#wikipedia-pt-bots' and user in users:
    flag = users[user][0]
    users[user][0] = mode == '+o' and '@' or \
      flag == '@' and mode == '-o' and '+' or \
      not flag and (mode == '+o' and '@' or mode == '+v' and '+') or \
      flag == '+' and mode == '-v' and ''

def quit(user, cloak):
  """
  Usuário saiu
  """
  user = user.split('!')[0]
  if user in users:
    del users[user]
  if user in log.avisos:
    log.avisos.remove(user)
    if not log.avisos:
      return '#wikipedia-pt-bots', u'Avisos AntiVandalismo desligados, para ligar use o comando !avisos'

def renamed(old, new):
  """
  Usuário alterou o nick
  """
  if old in users:
    users[new] = users[old]
    del users[old]
  if old in log.avisos:
    log.avisos.remove(old)
    log.avisos.add(new)

def url(txt):
  """
  Troca "X(Y)" por "X%28Y%29" para tornar os links clicáveis
  """
  return txt.replace(u' ', u'_').replace(u'(', u'%28').replace(u')', u'%29')

def parseLink(link, channel, template=False):
  """
  Expande wikilinks
  """
  if template and link[0:6] == u'subst:':
    return
  link = link.replace(' ', '_').split(':')
  wiki = channel in channels and prefixes[channels[channel]] or prefixes[u'w']
  if len(link) == 1 or template:
    return wiki + (template and link[0].lower() != u'predefinição' and u'Predefinição:' or u'') + url(u':'.join(link))
  elif link[0].lower() not in prefixes and len(link[0]) != 2:
    return wiki + url(u':'.join(link))
  else:
    link[0] = link[0].lower()
    prefix = link[0] in prefixes and prefixes[link[0]] or u'https://{}.wikipedia.org/wiki/'.format(link[0])
    return prefix + url(u':'.join(link[1:]))

class dbDict(dict):
  def __setitem__(self, key, value):
    dict.__setitem__(self, key, value)
    self.sync()

  def sync(self):
    global db
    with open('db.json', 'w') as f:
      json.dump(db, f)

  def parse(self, key, msg, name='o item', equal=False):
    if key not in self:
      return u'Erro: chave "%s" não existe no bd' % key
    if type(self[key]) != list:
      return u'Erro: chave "%s" do bd não é lista' % key
    elif msg == '':
      return u', '.join(self[key])
    for action in ('+ ', '- ', '= '):
      if msg.startswith(action):
         items = [i.strip() for i in msg[len(action):].split(',')]
         break
    else:
      return u'Erro: ação de bd local desconhecida'
    if action == '= ':
      if not equal:
        return u'ação não permitida, adicione ou remova os itens individualmente'
      if set(self[key]) == set(items):
        return u'já era isso que estava no bd'
      self[key] = items
      self.sync()
      return u', '.join(items)
    sync = False
    resp = []
    for item in items:
      if action == '+ ':
        if item in self[key]:
          resp.append(u'%s "%s" já estava na lista' % (name, item))
          continue
        self[key].append(item)
        resp.append(u'%s "%s" foi adicionad%s à lista' % (name, item, u'a' if name[0] == u'a' else u'o'))
        sync = True
      elif action == '- ':
        if item not in self[key]:
          resp.append(u'%s "%s" já não estava na lista' % (name, item))
          continue
        self[key].remove(item)
        resp.append(u'%s "%s" foi removid%s da lista' % (name, item, u'a' if name[0] == u'a' else u'o'))
        sync = True
    if sync:
      self.sync()
    return listar(resp)

  def append(self, key, item):
    if key not in self:
      self[key] = [item]
      return True
    if item in self[key]:
      return False
    self[key].append(item)
    self.sync()
    return True

  def remove(self, key, item):
    if key not in self or item not in self[key]:
      return False
    self[key].remove(item)
    self.sync()
    return True

with open('db.json') as f:
  db = json.load(f, object_hook=dbDict)

def labsmsg(msg):
  """
  Recebe mensagens de programas ou usuários dentro do labs
  igual ao relay do wm-bot
  """
  if msg.startswith(('#wikipedia-pt-bots ', '#wikipedia-pt-tecn ')):
    # limita a menssagem a 450 caracteres ascii sem quebrar um utf-8 no meio
    m = msg[19:469].decode('utf-8', 'ignore').encode('utf-8')
    return msg[:18], m

def phabFeed(msg, user):
  for name in db['phab']:
    if name in msg:
      return '#wikipedia-pt-tecn', msg.replace(name, u'\x1f' + name + u'\x1f')
