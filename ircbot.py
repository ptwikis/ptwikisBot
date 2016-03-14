#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Robô ptwikisBot no freenode, usado nos canais wikimedia de língua portuguesa.

@autor:   [[Usuário:Danilo.mac]]
@licença: GNU General Public License 3.0 (GPL V3)
"""

from twisted.words.protocols import irc
from twisted.internet import reactor, protocol

import re, gdbm, time
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
  with open('.password') as p:
    password = p.read()

  def __init__(self):
    """
    Inicia a classe de registro de avisos.

    Ao manter essa instância neste módulo os registrsos
    não são perdidos quando o módulo boottols é recarregado.
    """
    bottools.log = bottools.Log()


  def signedOn(self):
    """
    Chamado quando o robô se conecta ao servidor com sucesso.
    """
    self.msg('NickServ', 'GHOST ' + self.nickname + ' ' + self.password)
    self.msg('Nickserv', 'IDENTIFY ' + self.password)
    time.sleep(15)
    for channel in bottools.channels:
      self.join(channel)
      time.sleep(1)

  def irc_ERR_NICKNAMEINUSE(self, nick, params):
    """
    Dá um ghost no nick caso alguém o esteja usando ou
    o robô se reconectar antes do nick cair.
    """
    self.msg('NickServ', 'GHOST ' + self.nickname + ' ' + self.password)
    self.setNick(self.nickname)
    self.msg('Nickserv', 'IDENTIFY ' + self.password)

  def joined(self, channel):
    """
    Chamado quando entra em um canal.
    
    Se entrar em #wikipedia-pt-bots chama um WHO para ver
    quem está no canal.    
    """
    if channel == '#wikipedia-pt-bots':
      self.sendLine('WHO #wikipedia-pt-bots')

  def msg(self, channel, message, *args):
    """
    Envia mensagem para um canal.
    """
    if not isinstance(message, basestring):
      return
    if isinstance(message, unicode):
      message = message.encode('utf-8')
    irc.IRCClient.msg(self, channel, message, *args)

  def cloak(self, user, channel=None):
    """
    Verifica se o usuário tem cloak wikimedia, retorna o cloak
    se tiver, envia uma menssagem para o canl se não tiver.
    """
    user = user.split('@', 1)[1]
    for cloak in cloaks:
      if user.startswith(cloak):
        return user
    if channel:
      self.msg(channel, 'Autorizado apenas para usuários com cloak wikimedia')
    return False

  otherbots = ('wikimedia/-jem-/bot/AsimovBot', 'wikimedia/bot/wm-bot', 'wikimedia/bot/SirBot')

  def privmsg(self, user, channel, msg):
    """
    Chamado quando o robô recebe uma mensagem.
    """
    # Ignora outros robôs
    if user.split('@')[1] in self.otherbots:
      return
    msg = decode(msg)

    # Verifica se alguém está mandando mensagem em privado
    if channel == self.nickname:
      msg = 'Não aceito comandos em privado'
      self.msg(user.split('!')[0], msg)
      return

    # Chamada a adiministradores
    elif msg.startswith(u'!admin') and channel != '#wikipedia-pt':
      self.msg('#wikipedia-pt', user.split('!')[0] + ' chama administradores em ' + channel)

    # Comandos
    comando = msg.startswith(u'ptwikisBot:') and msg[11:].strip() or bottools.testcmd(msg)
    if comando:
      if comando.startswith('entre em ') and channel == '#wikipedia-pt-ops' and self.cloak(user, channel):
        self.join(comando[9:].encode('utf-8'))
      elif comando == 'saia' and self.cloak(user, channel):
        self.leave(channel)
      elif comando == 'reload' and self.cloak(user, channel):
        bottools.botDB.close()
        try:
          reload(bottools)
        except Exception as e:
          self.msg(channel, 'Erro: ' + repr(e))
          bottools.botDB = bottools.gdbm.open(bottools.dbfile, 'ws')
        else:
          self.msg(channel, 'Funções recarregadas')

      # Comandos que podem ser chamados em qualquer canal e cuja a resposta é
      # dada no mesmo canal do comando devem ser colocados na função cmd do
      # bottools, isso facilta a implementação, testes e correções. Após
      # adicionar uma nova função em bottools.cmd use o comando !reload para
      # recarregar o módulo bottools sem precisar reiniciar o robô.
      else:
        reactor.callInThread(self.cmdThread, comando, channel, user.split('!')[0], self.cloak(user))

    # Outras mensagens são processadas pelo bottools.msg
    else:
      resp = bottools.noCmd(msg, channel, user)
      if resp:
        self.msg(channel, resp)

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
    TODO: o processamento da menssagem está duplicado em msg()
    """
    for resp in (hasattr(resps, '__iter__') and resps or (resps,)):
      if not resp or not isinstance(resp, basestring):
        continue
      if isinstance(resp, unicode):
        resp = resp.encode('utf-8')
      if resp[0:5] == '/raw ' and len(resp) > 6:
        self.sendLine(resp[5:])
      else:
        self.msg(channel, resp)

  def RC(self, msg):
    """
    Recebe as mudanças recentes do canal pt.wikipedia no irc.wikimedia.org,
    as mensagem são recebidas pré-processadas no formato:
    [u'página', u'indicadores', u'url', u'usuário', u'(±dif)', u'sumário']
    o que é enviado à função RC no bottools, a qual deve retornar o canal e
    a mensagem a ser enviada.
    """
    resp = bottools.RC(msg)
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.msg(resp[0], resp[1])

  def irc_RPL_WHOREPLY(self, server, user):
    """
    Recebe os nomes de quem está nos canais após um comando WHO.
    """
    cloak = [c for c in cloaks if user[3].startswith(c)] and user[3] or None
    bottools.whoreplay(user[5], ('@' in user[6] or '+' in user[6]) and user[6][-1] or '', cloak)

  def irc_JOIN(self, user, params):
    """
    Recebe a notificação de que alguém entrou em uma canal.
    """
    channel = params[-1]
    resp = bottools.join(user, channel, self.cloak(user))
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.cmd(resp[1], resp[0])

  def irc_QUIT(self, user, params):
    """
    Recebe a notificação de que alguém saiu (não de um canal mas do IRC).
    """
    resp = bottools.quit(user, self.cloak(user))
    if type(resp) == tuple and len(resp) == 2 and resp[0][0] == '#':
      self.cmd(resp[1], resp[0])

  def userRenamed(self, old, new):
    """
    Recebe a notificação de que alguém mudou de nome.
    """
    bottools.renamed(old, new)

  def modeChanged(self, user, channel, set, mode, args):
    """
    Recebe a notificação de que alguém mudou de modo (voice, op)
    em um canal.
    """
    bottools.modeChanged(args[0], channel, (set and '+' or '-') + mode)

class BotFactory(protocol.ClientFactory):
  """
  Inicia o protocolo do robô do freenode e reinicia quando
  perde a conexão.
  """

  def buildProtocol(self, addr):
    """
    Construtor do protocolo.
    """
    p = Bot()
    p.factory = self
    self.bot = p
    print 'BuildProtocol Bot'
    return p

  def clientConnectionLost(self, connector, reason):
    """
    Se desconectar, reconecta ao servidor.
    """
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
    self.join('#pt.wikipedia')

  def privmsg(self, user, channel, msg):
    """
    Chamado quando o robô recebe uma menssagem.
    """

    msg = self.reMsg.search(decode(msg)) # [u'página', u'indicadores', u'url', u'usuário', u'(±dif)', u'sumário']
    if msg:
      msg = list(msg.groups())
      msg[5] = self.reColors.sub(u'', msg[5]) # removendo as cores do sumário
      self.botFactory.bot.RC(msg) # envia menssagem para a função RC do robô do freenode

class RCFactory(protocol.ClientFactory):
  """
  Inicia o protocolo do robô do irc.wikimedia.org que envia as mudanças recentes.
  """
  
  def __init__(self, botFactory):
    """
    Ao criar uma instância recebe em botFactory o construtor do protocolo
    do robô do freenode e armazena em self.botFactory.
    """
    self.botFactory = botFactory

  def buildProtocol(self, addr):
    """
    Construtor do protocolo.

    Ao passar self.botFactory (cosntrutor do freenode) para o protocolo do
    robô, permite que o robô do irc.wikimedia chame funções do robô do freenode.
    """
    p = RCfeed()
    p.factory = self
    p.botFactory = self.botFactory
    return p

  def clientConnectionLost(self, connector, reason):
    """
    Se desconectar, reconecta ao servidor.
    """
    connector.connect()

  def clientConnectionFailed(self, connector, reason):
    """
    Chamado quando a conexão falha.
    """
    print "irc.wikimedia connection failed:", reason


if __name__ == '__main__':    
  # Cria um construtor de protocolo
  bot = BotFactory()
  rc = RCFactory(bot) # passa bot como argumento para poder se comunicar com o robô do freenode

  # Conecta o construtor a esse host e porta
  reactor.connectTCP("irc.freenode.net", 6667, bot)
  reactor.connectTCP("irc.wikimedia.org", 6667, rc)

  # Rodar roboôs
  reactor.run()
