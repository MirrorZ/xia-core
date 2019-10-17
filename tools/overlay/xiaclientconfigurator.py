
# XIA network configuration service

# Starts with a config file with format:
#  [<router_name>]
#     ControlAddress = <dot_separated_ip_addr>
#     HostInterface  = <interface_to_which_AID_hosts_connect>
#     Peer_<n>       = <peer_name>:<iface>
# where, <n> lets the router have a number of peers
#

import os
import sys

from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol

# Bring in xia and overlay tools into path
srcdir = os.getcwd()[:os.getcwd().rindex('xia-core')+len('xia-core')]
sys.path.append(os.path.join(srcdir, 'bin'))
sys.path.append(os.path.join(srcdir, 'tools/overlay'))

import xiapyutils
import clientconfig_pb2

from ConfigParser import RawConfigParser

import inspect

class XIAClientConfigReader:
    def __init__(self, config_filename):
       self.routers = {}
       self.default_router = {}
       self.control_addr = {}
       self.control_port = {}
       self.ad = {}
       self.hid = {}

       # Read in the config file
       parser = RawConfigParser()
       parser.read(config_filename)

       # Router names are the section names in the config file
       clients = parser.sections()
       if len(clients) == 0:
       		print "ERROR: No sections found in config file"

       # Read in info into our internal data structures
       for client in clients:

           # Interface names for each router (comma separated list)
           routers = parser.get(client, 'Routers')
           routers = routers.replace(' ', '')
           self.routers[client] = routers.split(',')

           self.default_router[client] = parser.get(client, 'Default')
           self.control_addr[client] = parser.get(client, 'ControlAddress')
           self.control_port[client] = parser.get(client, 'ControlPort')

    def clients(self):
        return self.routers.keys()

class ConfigClient(Int32StringReceiver):
    def __init__(self, client, configurator):
        print inspect.stack()[0][3]
        self.client = client
        self.configurator = configurator

    def connectionLost(self, reason):
        self.configurator.connected_clients.remove(self)
        if len(self.configurator.connected_clients) == 0:
            reactor.stop()

    def connectionMade(self):
        self.sendConfig()

    def sendConfig(self):
        response = clientconfig_pb2.Config()
        response.type = clientconfig_pb2.Config.CLIENT_CONFIG
        response.name = self.client
        response.router_addr = self.default_router
        response.AD = self.ad
        response.HID = self.hid

        self.sendString(response.SerializeToString())


class XIAClientConfigurator():
	def __init__(self, configurator):
		self.configurator = configurator
		self.connected_clients = {}

		clientConfig = XIAClientConfigReader('tools/overlay/client.conf')
    	for client in clientConfig.clients():
        	print client + ':'
        	for router in clientConfig.routers[client]:
            	clientConfig.ad[client] = configurator.xids[router][0]
            	clientConfig.hid[client] = configurator.xids[router][1]
            	print configurator.xids[router]

        self.clientConfig = clientConfig

	def configureClient(self):
        for client in self.clientConfig.clients():

            endpoint = TCP4ClientEndpoint(reactor, 
                self.clientConfig.control_addr[client],
                int(self.clientConfig.control_port[client]))

            d = connectProtocol(endpoint, self.ConfigClient(client, self))
            d.addCallback(self.addClient)

        reactor.run()

    def addClient(self, client):
        self.connected_clients.append(client)
