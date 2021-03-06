#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Robô ptwikisBot no freenode, usado nos canais wikimedia de língua portuguesa.

@autor:   [[Usuário:Danilo.mac]]
@licença: GNU General Public License 3.0 (GPL V3)
"""

from twisted.words.protocols import irc
from twisted.internet import reactor, protocol

import re, time, os
import bottools

cloaks = ('wikipedia/', 'wikimedia/', 'wikibooks/', 'wikinews/', 'wikiquote/', 'wiktionary/', 'wikisource/', 'wikivoyage/', 'wikiversity/')

def decode(txt):
  """
  Decodifica o código que pode estar em utf-8 ou latim1
  """
  try:
    txt = txt.decode('utf-8')
  except:
    txt = txt.decode('latin1')
  return txt

class Bot(irc.IRCClient):
  """
  Robô que fica no freenode
  """
  nickname = 'ptwikisBot'
  username = 'ptwikisBot'

  whoisArgs = {}
  users = {}
  lists = {}
  names = {}

  def __init__(self):
    """
    Chamado quando uma instância do robô é iniciada.
    Inicia a classe de registro de avisos e estabelece
    bottools.users como referencia para self.users, e o
    mesmo para lists. Dessa forma log e users não serão
    perdidos quando bottools é recarregado.
    """
    bottools.log = bottools.Log()
    bottools.lists = self.lists
    bottools.users = self.users

  def signedOn(self):
    """
    Chamado quando o robô se conecta ao servidor com sucesso.
    """
    with open('.password') as p:
      password = p.read()
    self.msg('Nickserv', 'IDENTIFY ptwikisbot ' + password)

  def irc_396(self, prefix, params):
    """
    Recebe notificação que foi identificado
    """
    if self.nickname != 'ptwikisBot':
       self.sendLine('NS REGAIN ptwikisBot')
    if params[1] == 'wikimedia/bot/ptwikisbot':
       self.joinChannels()
    else:
       self.irc_unknown(prefix, '396', params)

  def joinChannels(self):
    """
    Faz o robô entrar nos canais configurados
    """
    for channel in bottools.channels:
      self.join(channel)
      time.sleep(1)
    for channel in bottools.feedChan:
      self.join(channel)

  def irc_ERR_NICKNAMEINUSE(self, nick, params):
    """
    Dá um ghost no nick caso alguém o esteja usando ou
    o robô se reconectar antes do nick cair.
    """
    self.msg('NickServ', 'REGAIN ptwikisBot')

  def msg(self, channel, message, *args):
    """
    Envia mensagem para um canal.
    """
    if not isinstance(message, basestring):
      return
    if isinstance(message, unicode):
      message = message.encode('utf-8')
    irc.IRCClient.msg(self, channel, message, *args)

  def cloak(self, user):
    """
    Verifica se o usuário tem cloak wikimedia, retorna o cloak
    se tiver, envia uma menssagem para o canl se não tiver.
    """
    user = user.split('@', 1)[1] if '@' in user else user
    for cloak in cloaks:
      if user.startswith(cloak):
        return user

  otherbots = ('wikimedia/-jem-/bot/AsimovBot', 'wikimedia/bot/wm-bot', 'wikimedia/bot/SirBot', 'services.')

  def privmsg(self, user, channel, msg):
    """
    Chamado quando o robô recebe uma mensagem.
    """
    # Ignora outros robôs
    if user.split('@')[1] in self.otherbots:
      return
    msg = decode(msg)

    # Feed do phabricator
    if channel in bottools.feedChan:
      resp = bottools.phabFeed(msg, user)
      if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
        self.msg(resp[0], resp[1])
      return

    # Verifica se alguém está mandando mensagem em privado
    if channel == self.nickname:
      msg = 'Não aceito comandos em privado'
      self.msg(user.split('!')[0], msg)
      return

    # Comandos
    comando = msg.startswith(u'ptwikisBot:') and msg[11:].strip() or bottools.testcmd(msg)
    if comando:
      if comando == 'reload' and self.cloak(user) in bottools.db['operador']:
        try:
          reload(bottools)
        except Exception as e:
          self.msg(channel, 'Erro: ' + repr(e))
        else:
          self.msg(channel, 'Funções recarregadas')
      elif comando == 'reconnect':
        if hasattr(self, 'rcconnector'):
          self.rcconnector.connect()
          self.msg(channel, u'tentando reconectar ao irc.wikimedia')
          del self.rcconnector
      elif comando == 'restart' and self.cloak(user) in bottools.db['operador']:
        global restart
        restart = True
        self.sendLine('QUIT Restart')
        reactor.callLater(5, reactor.stop)

      # Comandos que podem ser chamados em qualquer canal e cuja a resposta é
      # dada no mesmo canal do comando devem ser colocados na função cmd do
      # bottools, isso facilta a implementação, testes e correções. Após
      # adicionar uma nova função em bottools.cmd use o comando !reload para
      # recarregar o módulo bottools sem precisar reiniciar o robô.
      else:
        reactor.callInThread(self.cmdThread, comando, channel, user, self.cloak(user))

    # Outras mensagens são processadas pelo bottools.noCmd
    else:
      resp = bottools.noCmd(msg, channel, user)
      if resp:
        self.cmd(resp, channel)

  def cmdThread(self, comando, channel, user, cloak):
    """
    Faz o comando ser processado por outra Thead para evitar
    que o processamento demorado de um comando paralise as outras
    funções do robô.
    """
    resp = bottools.cmd(comando, channel, user, cloak)
    if resp:
      reactor.callFromThread(self.cmd, resp, channel)

  def cmd(self, resps, channel):
    """
    Envia uma menssagem para um canal ou um comando crú
    para o servidor irc.
    """
    for resp in (hasattr(resps, '__iter__') and resps or (resps,)):
      if not resp or not isinstance(resp, basestring):
        continue
      if isinstance(resp, unicode):
        resp = resp.encode('utf-8')
      if resp in bottools.channels:
        channel = resp
        continue
      if resp[0:5] == '/raw ' and len(resp) > 6:
        self.sendLine(resp[5:])
      else:
        self.msg(channel, resp)

  def RC(self, channel, msg):
    """
    Recebe as mudanças recentes do canal pt.wikipedia no irc.wikimedia.org,
    as mensagem são recebidas pré-processadas no formato:
    [u'página', u'indicadores', u'url', u'usuário', u'(±dif)', u'sumário']
    o que é enviado à função RC no bottools, a qual deve retornar o canal e
    a mensagem a ser enviada.
    """
    resp = bottools.RC(channel, msg)
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.msg(resp[0], resp[1])

  def labsmsg(self, msg):
    """
    Recebe mensagens de programas ou usuários dentro do Labs, processa a
    menssagem pelo botttols.labsmsg e envia a resposta a um canal se
    houver retorno da função.
    """
    resp = bottools.labsmsg(msg)
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.msg(resp[0], resp[1])

  def irc_JOIN(self, user, params):
    """
    Recebe a notificação de que alguém entrou em uma canal.
    """
    nick = user.split('!')[0]
    if nick == self.nickname:
       return
    channel = params[-1]
    self.users[channel][nick] = 0
    self.users.setdefault(nick, {}).update({'host': user.split('@')[1]})
    cloak = self.cloak(user)
    if cloak:
      self.users[nick]['cloak'] = cloak
    resp = bottools.join(user, channel, self.cloak(user))
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.cmd(resp[1], resp[0])

  def irc_QUIT(self, user, params):
    """
    Recebe a notificação de que alguém saiu (não de um canal mas do IRC).
    """
    nick = user.split('!')[0]
    for chan in self.users:
      if chan[0] != '#':
        continue
      if nick in self.users[chan]:
        del self.users[chan][nick]
    resp = bottools.quit(user.split('!')[0])
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.cmd(resp[1], resp[0])
    if nick in self.users:
      del self.users[nick]

  def userLeft(self, nick, channel):
    """
    Recebe notificação que alguém saiu de um canal (não do IRC)
    """
    if nick in self.users[channel]:
      del self.users[channel][nick]
    if nick in self.users and nick not in {n for c in self.users if c[0] == '#' for n in self.users[c]}:
      del self.users[nick]

  def userKicked(self, kicked, channel, kicker, message):
    """
    Chamado quando alguém é chutado de um canal
    """
    self.userLeft(kicked, channel)

  def left(self, channel):
    """
    Chamado quando o robô sai de um canal (não do IRC)
    """
    del self.users[channel]
    allNicks = {n for c in self.users if c[0] == '#' for n in self.users[c]}
    for nick in [n for n in self.users if n[0] != '#']:
      if nick not in allNicks:
        del self.users[nick]

  def userRenamed(self, old, new):
    """
    Recebe a notificação de que alguém mudou de nick.
    """
    for item in self.users.keys():
      if item[0] == '#' and old in self.users[item]:
        self.users[item][new] = self.users[item][old]
        del self.users[item][old]
      elif item == old:
        self.users[new] = self.users[old]
        del self.users[old]
    bottools.renamed(old, new)

  def irc_RPL_WHOISUSER(self, prefix, params):
    """
    Recebe dados de whois referente ao host do usuário
    """
    self.whoisArgs[params[1]] = {'host': params[3]}
    ip = re.search(ur'@.*?(\d{1,3}([.-])\d{1,3}\2\d{1,3}\2\d{1,3})', params[3])
    if ip:
      self.whoisArgs['ip'] = ip.group(1).replace('-', '.')

  def irc_RPL_WHOISCHANNELS(self, prefix, params):
    """
    Recebe dados de whois referente aos canais em que o usuário está
    """
    self.whoisArgs[params[1]]['channels'] = [c[1:] if c[0] != '#' else c for c in params[2].split()]

  def irc_330(self, prefix, params):
    """
    Recebe dados de whois referente ao nome de usuário registrado
    """
    self.whoisArgs[params[1]]['user'] = params[2]

  def irc_RPL_ENDOFWHOIS(self, prefix, params):
    """
    Fim da lista de whois, os dados são enviados à função bottools.kickban
    """
    if params[1] in self.whoisArgs:
      resp = bottools.kickban(params[1], self.whoisArgs[params[1]])
      if resp:
        self.cmd(resp, '#wikipedia-pt-ops')
      del self.whoisArgs[params[1]]

  def irc_RPL_NAMREPLY(self, prefix, params):
    """
    Recebe nomes de quem está no canal
    params[2] é o canal, params[3] é a lista de nicks (@nick = op e +nick = voice)
    """
    flags = {'@': 2, '+': 1}
    for nick in params[3].split():
      self.names.setdefault(params[2], {})[nick.strip('+@')] = flags.get(nick[0], 0)

  def irc_RPL_ENDOFNAMES(self, prefix, params):
    """
    Fim da lista de quem está no canal, envia lista para bottools.users
    params[1] é o canal
    """
    self.users[params[1]] = self.names[params[1]]
    del self.names[params[1]]
    if params[1] == '#wikipedia-pt':
      self.sendLine('WHO #wikipedia-pt')

  def irc_RPL_WHOREPLY(self, prefix, params):
    """
    Recebe a lista detalhada de quem está no canal (comando WHO)
    params[1] é o canal, params[5] é o nick, params[3] é o host
    """
    if params[5] == self.nickname:
      return
    self.users.setdefault(params[5], {}).update({'host': params[3]})
    cloak = self.cloak(params[3])
    if cloak:
      self.users[params[5]]['cloak'] = cloak

  def RPL_BANLIST(self, prefix, params):
    """
    Recebe itens da banlist
    params = ['ptwikisBot', '#canal', 'ban', 'op!que@baniu', 'unix timestamp']
    """
    self.lists.setdefault(params[1], {}).setdefault('ban', []).append((params[2], params[3], int(params[4])))

  def RPL_ENDOFBANLIST(self, prefix, params):
    """
    Fim da banlist
    """
    self.listProcess()

  def irc_728(self, prefix, params):
    """
    Recebe itens da quietlist
    params = ['ptwikisBot', '#canal', 'q', 'ban', 'op!que@silenciou', 'unix timestamp']
    """
    self.lists.setdefault(params[1], {}).setdefault('ban', []).append((params[3], params[4], int(params[5])))

  def irc_729(self, prefix, params):
    """
    Fim da quietlist
    """
    self.listProcess()

  def listProcess(self):
    """
    Processa fila de comandos para banlists e quietlists
    """
    if 'queue' not in self.lists:
      return
    if self.lists['queue']:
      self.sendLine(self.lists['queue'].pop(0))
    else:
      bottools.cleanBans()
      if self.lists.get('queue'):
        self.sendLine(self.lists['queue'].pop(0))

  def irc_MODE(self, user, params):
    """
    Recebe mudança em modo do canal
    params = ['#canal', 'modo (+b, -b, +q, -q, +v, +o, etc...)', 'argumento (ban mask, nick)']
    """
    if params[0] not in bottools.channels:
      return
    if params[1] in ('+b', '+q'):
      self.lists.setdefault(params[0], {}).setdefault('ban' if params[1] == '+b' else 'quiet', []).append(
        (params[2], user, int(time.time())))
    elif params[1] in ('-b', '-q'):
      lType = 'ban' if params[1] == '-b' else 'quiet'
      for i, b in enumerate([entry[0] for entry in self.lists.get(params[0], {}).get(lType, [])]):
        if b == params[2]:
          self.lists[params[0]][lType].pop(i)
          break
      if user.split('!')[0] == self.nickname:
        self.listProcess()
    elif params[1] in ('+v', '+o'):
      self.users[params[0]][params[2]] = 2 if params[1] == '+o' else 1
    elif params[1] in ('-v', '-o'):
      self.sendLine('NAMES ' + params[0])

  def noticed(self, user, channel, message):
    self.output('NOTICE from %s: %s' % (user.split('!')[0], message))

  def output(self, message):
    """
    Envia mensagem para o log do robô ou para o canal que
    estiver com o output ligado.
    """
    if hasattr(bottools, 'output') and bottools.output.startswith('#'):
      self.msg(bottools.output, message)
    else:
      print '[%s] %s' % (time.strftime('%d-%m-%Y %H:%M:%S'), message)

  def irc_unknown(self, prefix, command, params):
    """
    Recebe comandos que não foram processados por outras funções
    """
    if command in ('PONG', '333', '328'):
      return
    if prefix.endswith('freenode.net'):
      self.output('%s %r' % (command, params))
    else:
      self.output('%s %s %r' % (prefix, command, params))

  def rclost(self, reason, connector):
    """
    Notifica uma queda no irc.wikimedia
    """
    self.rcconnector = connector
    self.msg('#wikipedia-pt-bots', u'Falha na conexão com o irc.wikimedia (%s) use !reconnect para reconectar' % reason)

class BotFactory(protocol.ClientFactory):
  """
  Inicia o protocolo do robô do freenode e reinicia quando
  perde a conexão.
  """
  lastConnections = []

  def buildProtocol(self, addr):
    """
    Construtor do protocolo.
    """
    p = Bot()
    p.factory = self
    self.bot = p
    print 'BuildProtocol Bot %s' % time.strftime('%d-%m-%Y %H:%M:%S')
    return p

  def clientConnectionLost(self, connector, reason):
    """
    Se desconectar, reconecta ao servidor.
    """
    print '[%s] freenode connection lost:' % time.strftime('%d-%m-%Y %H:%M:%S'), reason
    self.lastConnections.append(int(time.time()))
    if sum(1 for t in self.lastConnections if t + 6000 > time.time()) > 6:
      reactor.stop()
      return
    if any(1 for t in self.lastConnections if t + 600 > time.time()):
      time.sleep(600)
    connector.connect()

  def clientConnectionFailed(self, connector, reason):
    """
    Chamado quando a conexão falha.
    """
    print "connection failed:", reason
    reactor.stop()

class RCfeed(irc.IRCClient):
  """
  Robô que fica no irc.wikimedia recebendo as mudanças recentes.
  """

  nickname = 'ptwikisBot'
  realname = 'ptwikisBot'

  reMsg = re.compile(ur'\x0314\[\[\x0307([^]\x03]+)\x0314\]\]\x034 ([^\x03 ]*)\x0310 \x0302([^\x03 ]*)\x03 \x035\*\x03 \x0303([^\x03]+)\x03 \x035\*\x03 (\([+-]?\d+\))? \x0310(.*?)\x03$')
  reColors = re.compile(ur'\x03(?:\d\d?| )')

  def signedOn(self):
    """
    Chamado quando o robô é conectado com sucesso ao servidor.
    """
    self.join('#pt.wikipedia,#pt.wikibooks,#pt.wikinews,#pt.wiktionary,#pt.wikiversity,#pt.wikisource,#pt.wikiquote,#pt.wikivoyage,#br.wikimedia,#meta.wikimedia')

  def privmsg(self, user, channel, msg):
    """
    Chamado quando o robô recebe uma menssagem.
    """

    msg = self.reMsg.search(decode(msg)) # [u'página', u'indicadores', u'url', u'usuário', u'(±dif)', u'sumário']
    if msg:
      msg = list(msg.groups())
      msg[5] = self.reColors.sub(u'', msg[5]) # removendo as cores do sumário
      bot.bot.RC(channel, msg) # envia menssagem para a função RC do robô do freenode

class RCFactory(protocol.ClientFactory):
  """
  Inicia o protocolo do robô do irc.wikimedia.org que envia as mudanças recentes.
  """
  
  def buildProtocol(self, addr):
    """
    Construtor do protocolo.
    """
    p = RCfeed()
    p.factory = self
    print 'BuildProtocol RC %s' % time.strftime('%d-%m-%Y %H:%M:%S')
    return p

  def clientConnectionLost(self, connector, reason):
    """
    Se desconectar, reconecta ao servidor.
    """
    print '[%s] irc.wikimedia connection lost:' % time.strftime('%d-%m-%Y %H:%M:%S'), reason
    connector.connect()

  def clientConnectionFailed(self, connector, reason):
    """
    Chamado quando a conexão falha.
    """
    print '[%s] irc.wikimedia connection failed:' % time.strftime('%d-%m-%Y %H:%M:%S'), reason
    bot.bot.rclost(repr(reason), connector)

class LabsMsg(protocol.Protocol):
    """
    Recebe mensagens de programas ou usuários dentro do Labs
    """
    def dataReceived(self, data):
        bot.bot.labsmsg(data)

class LabsFactory(protocol.ClientFactory):
  """
  Inicia o protocolo que recebe menssagens do Labs
  """
  def buildProtocol(self, addr):
    """
    Construtor do protocolo.
    """
    p = LabsMsg()
    p.factory = self
    return p

if __name__ == '__main__':    
  # Cria um construtor de protocolo
  bot = BotFactory()
  rc = RCFactory()
  labs = LabsFactory()
  labsPort = 10888 # que porta o robô está usando para receber mensagens do Labs

  # Salva o nome da instância em que o robô está rodando para que outros programas do labs 
  # saibam para onde as enviar mensagens
  with open('bothost', 'w') as f:
    f.write(os.uname()[1] + '.eqiad.wmflabs:' + str(labsPort))

  # Conecta o construtor a esse host e porta
  reactor.connectTCP("irc.freenode.net", 6667, bot)
  reactor.connectTCP("irc.wikimedia.org", 6667, rc)
  reactor.listenTCP(labsPort, labs)

  # Rodar roboôs
  reactor.run()

  # Restart
  if 'restart' in globals():
    raise Exception('Restarting') # sair com erro força o grid engine a reiniciar o processo
