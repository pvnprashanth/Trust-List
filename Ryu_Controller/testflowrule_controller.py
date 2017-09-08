from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.dpid import str_to_dpid
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib import hub
from ryu.lib import dpid as dpid_lib
from ryu.controller import mac_to_port
from ryu.lib.mac import haddr_to_bin
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.topology import event, switches
from ryu.topology import api
from ryu.controller import dpset

from webob import Response
import time
import datetime
import struct
from array import array
import six
from operator import attrgetter
from netaddr.ip import IPNetwork
from threading import Timer
import json
import logging
import socket
import collections
import os
import sys
import heapq
import networkx as nx
from webob.static import DirectoryApp


from web3 import Web3, KeepAliveRPCProvider, IPCProvider, RPCProvider

import web3.personal
import web3.admin
import web3.contract
import web3.db
import web3.eth
import web3.exceptions
import web3.formatters
import web3.iban
import web3.main
import web3.miner
import web3.net
import web3.txpool
import web3.utils.http
import web3.providers.manager
import web3.version
import web3.shh

from web3.admin import Admin
from web3.db import Db
from web3.eth import Eth
from web3.miner import Miner
from web3.net import Net
from web3.personal import Personal
from solc import compile_source
from ethjsonrpc import EthJsonRpc



media_stats_name = 'simple_switch_api_app'
url = '/mediastats/{dpid}'

PATH = os.path.dirname(__file__)
LOG = logging.getLogger('SimpleSwitchIgmp13')
LOG.setLevel(logging.INFO)
logging.basicConfig()

#global variables
start_time = 0.0
"""sent_time1=0.0
sent_time2=0.0
sent_time3=0.0
sent_timelink=0.0
received_time1 = 0.0
received_time2 = 0.0
src_dpid=0
dst_dpid=0
src_hwr=0
dst_hwr=0
mytimer = 0
OWD1=0.0
OWD2=0.0"""
switch_links = {}
flag=0
t=0
probe_value = 5577
s = "aaaaaaaaaaa9"
multicast_tree = {}
destination = []
receiver = {}
apps_json = {}
ports = []

devices_json = {}

mac_json = {}

server_gateway = "2-1"
iot_range = ('10.0.0.1', '10.0.0.2')

#apps_json2 = {u'Smart_Building': {'appIPaddr': u'192.168.0.1', 'appPort': u'34567', 'appURL': u'http://www.smartbuilding.com', 'appProtocol': u'tcp', 'appName': u'Smart_Building'}, u'Smart_Home': {'appIPaddr': u'192.168.0.1', 'appPort': u'2004', 'appURL': u'http://www.smarthome.com', 'appProtocol': u'tcp', 'appName': u'Smart_Home'}, u'Theft_Detection': {'appIPaddr': u'192.168.0.1', 'appPort': u'39493', 'appURL': u'http://www.theftdetectionm.com', 'appProtocol': u'tcp', 'appName': u'Theft_Detection'}, u'Home_Automation': {'appIPaddr': u'192.168.0.1', 'appPort': u'43950', 'appURL': u'http://www.homeautomation.com', 'appProtocol': u'udp', 'appName': u'Home_Automation'}, u'Smart_City': {'appIPaddr': u'192.168.0.1', 'appPort': u'56987', 'appURL': u'http://www.smartcity.com', 'appProtocol': u'tcp', 'appName': u'Smart_City'}, u'Smart_Voting': {'appIPaddr': u'192.168.0.1', 'appPort': u'22100', 'appURL': u'http://www.smartvoting.com', 'appProtocol': u'tcp', 'appName': u'Smart_Voting'}, u'Garbage_Monitoring_System': {'appIPaddr': u'192.168.0.1', 'appPort': u'19003', 'appURL': u'http://www.garbagemonitoringsystem.com', 'appProtocol': u'tcp', 'appName': u'Garbage_Monitoring_System'}}
'''apps_json2 = {u'Smart_Home': {'appIPaddr': u'192.168.0.1', 'appPort': u'2004', 'appURL': u'http://www.smarthome.com', 'appProtocol': u'tcp', 'appName': u'Smart_Home'}}
ports2 = [u'tcp-34567', u'tcp-2004', u'tcp-39493', u'udp-43950', u'tcp-56987', u'tcp-22100', u'tcp-19003']

devices_json2 = {u'1e:6c:f7:5e:ba:e7': {'IP': u'10.0.0.1 ', 'MAC': u'1e:6c:f7:5e:ba:e7', 'myApps': u'Smart_Building,'}}'''


apps_json2 = {u'Smart_Home': {'appIPaddr': u'192.168.0.1', 'appPort': u'2004', 'appURL': u'http://www.smarthome.com', 'appProtocol': u'tcp', 'appName': u'Smart_Home'}}
ports2 = [u'tcp-34567', u'tcp-2004', u'tcp-39493', u'udp-43950', u'tcp-56987', u'tcp-22100', u'tcp-19003']

devices_json2 = {u'ce:c4:e5:46:df:36': {'IP': u'10.0.0.1 ', 'MAC': u'ce:c4:e5:46:df:36', 'myApps': u'Smart_Home,Smart_Building,'}}


class ArpTable(object):
    def __init__(self, hostIpAddr, hostMacAddr, routerPort):
        self.hostIpAddr = hostIpAddr
        self.hostMacAddr = hostMacAddr
        self.routerPort = routerPort

    def get_mac(self):
        return self.hostMacAddr

    def get_all(self):
        return self.hostIpAddr, self.hostMacAddr, self.routerPort
class PortTable(object):
    def __init__(self, routerPort, routerIpAddr, routerMacAddr, routeDist):
        self.routerPort = routerPort
        self.routerIpAddr = routerIpAddr
        self.routerMacAddr = routerMacAddr
        self.routeDist = routeDist

    def get_ip(self):
        return self.routerIpAddr

    def get_all(self):
        return self.routerIpAddr, self.routerMacAddr, self.routerPort, self.routeDist
class Vertex:
    def __init__(self, node):
        self.id = node
        self.adjacent = {}
        # Set distance to infinity for all nodes
        self.distance = sys.maxint
        # Mark all nodes unvisited        
        self.visited = False  
        # Predecessor
        self.previous = None

    def add_neighbor(self, neighbor, weight=0):
        self.adjacent[neighbor] = weight

    def get_connections(self):
        return self.adjacent.keys()  

    def get_id(self):
        return self.id

    def get_weight(self, neighbor):
        return self.adjacent[neighbor]

    def set_distance(self, dist):
        self.distance = dist

    def get_distance(self):
        return self.distance

    def set_previous(self, prev):
        self.previous = prev

    def set_visited(self):
        self.visited = True

    def __str__(self):
        return str(self.id) + ' adjacent: ' + str([x.id for x in self.adjacent])

class Graph:
    def __init__(self):
        self.vert_dict = {}
        self.num_vertices = 0

    def __iter__(self):
        return iter(self.vert_dict.values())

    def add_vertex(self, node):
        self.num_vertices = self.num_vertices + 1
        new_vertex = Vertex(node)
        self.vert_dict[node] = new_vertex
        return new_vertex

    def get_vertex(self, n):
        if n in self.vert_dict:
            return self.vert_dict[n]
        else:
            return None

    def add_edge(self, frm, to, cost = 0):
        if frm not in self.vert_dict:
            self.add_vertex(frm)
        if to not in self.vert_dict:
            self.add_vertex(to)

        self.vert_dict[frm].add_neighbor(self.vert_dict[to], cost)
        self.vert_dict[to].add_neighbor(self.vert_dict[frm], cost)

    def get_vertices(self):
        return self.vert_dict.keys()

    def set_previous(self, current):
        self.previous = current

    def get_previous(self, current):
        return self.previous 

class GUIServerController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GUIServerController, self).__init__(req, link, data, **config)
        path = "%s/html/" % PATH
        self.static_app = DirectoryApp(path)

    @route('topology', '/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)

class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[media_stats_name]

    """@route('mediastats', url, methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simpl_switch_spp
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)"""

    @route('mediastats', url, methods=['PUT'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_media_stats(self, req, **kwargs):

        simple_switch = self.simpl_switch_spp
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        #new_entry = eval(req.body)
        #print "new_entry:",new_entry
        print "statistics for the media:",req.body
        """if dpid not in simple_switch.mac_to_port:
            return Response(status=404)"""

        """try:
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)"""




class SimpleSwitchIgmp13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib, 'stplib': stplib.Stp}
    #_CONTEXTS = {'igmplib': igmplib.IgmpLib, 'wsgi': WSGIApplication, 'switches': switches.Switches,}
    _CONTEXTS = {'wsgi': WSGIApplication, 'switches': switches.Switches,}
    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIgmp13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ping_q = hub.Queue()
        self.portInfo = {}
        self.arpInfo = {}
        self.routingInfo = {}
        self.link_dist = {}
        self.port_stats = {}
        self.port_speed = {}
        self.access_table = {}
        self.ARP_table = {}
        self.sleep = 5

        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {media_stats_name : self})
        #wsgi.register(GUIServerController)    
        #self._snoop = kwargs['igmplib']------------------
        # if you want a switch to operate as a querier,
        # set up as follows:
        #self._snoop.set_querier_mode(dpid=1, server_port=3)-------------------
        #self._snoop.set_querier_mode(dpid=str_to_dpid('0000000000000001'), server_port=2)
        #self.stp = kwargs['stplib']
        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        """config = {dpid_lib.str_to_dpid('0000000000000001'):
                     {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                     {'bridge': {'priority': 0x9000}}}
        self.stp.set_config(config)"""   
        #self.dpset = kwargs['dpset'] 
        #self.create_graph()
        # dpid         the datapath id that will operate as a querier.
        # server_port  a port number which connect to the multicast
        #              server.
        #
        # NOTE: you can set up only the one querier.
        # when you called this method several times,
        # only the last one becomes effective.
        self.timestamp=0
        self.datapaths = {}
        #global start_time
        #start_time = time.time() * 1000
        #print "start_time:", start_time
        '''for key in apps_json2:
            IP_address = apps_json2[key]['appIPaddr']
            protocol = apps_json2[key]['appProtocol']
            port_no = apps_json2[key]['appPort']
            print 'IP_address', IP_address
            print 'protocol', protocol
            print 'port_no', port_no'''
        self.monitor_thread = hub.spawn(self._monitor)


        
    
    def _monitor(self):
        global switch_links, destination, apps_json, ports
        hub.sleep(10)
        '''while True:

            for key in devices_json2:
                src_mac = key
                scr_ip = devices_json2[key]['IP']
                myapps1 = devices_json2[key]['myApps'].split(",")
                print myapps1
                
                for i in range(0, len(myapps1)-1, 1):
                    if myapps1[i] in apps_json2:
                        dst_ip = apps_json2[myapps1[i]]['appIPaddr']
                        dst_port = apps_json2[myapps1[i]]['appPort']
                        proto = apps_json2[myapps1[i]]['appProtocol']
                        print 'src_mac, scr_ip, dst_ip, dst_port, proto', src_mac, scr_ip, dst_ip, dst_port, proto 
                        source1 = '1-1'
                        dest1 = '2-1'
                        self.create_graph_permanent(source1, dest1, src_mac, scr_ip, dst_ip, dst_port, proto)

            hub.sleep(10)'''
         
        while True:
            #print(switch_links)
            file = open("pri_flrule.txt","a")
            #print "file:", file
            apps_json1 = {}
            devices_json1 = {}
            ports1 = []
	    web3 = Web3(IPCProvider())
            #web3 = Web3(IPCProvider('/home/prashanth/.ethereum/geth.ipc'))
            #obj = web3.Web3(web3.HTTPProvider('http://192.168.233.133:8111'))
            #psn = web3.personal.Personal(obj)
            web3.personal.unlockAccount(web3.eth.accounts[0],"prashanth",1000) #replace 123456 to your Ethereum accounts password

            #abi = [{u'inputs': [], u'constant': True, u'name': u'getAllIOT_Devices', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp1', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'removeApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'addAppToUser', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'constant': True, u'name': u'getAllApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': False, u'name': u'removeIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': True, u'name': u'getAppDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'data1'}], u'constant': False, u'name': u'registerNewIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'IP'}, {u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'registerNewIOT_Device1', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'type': u'constructor', u'payable': True}]

            #contract_address = '0x1614f85a270c1454ffa6f035f03fdd16df428294'

            abi = [{u'inputs': [], u'constant': True, u'name': u'getAllIOT_Devices', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'removeApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'IP'}, {u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'registerNewIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'addAppToUser', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'constant': True, u'name': u'getAllApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': False, u'name': u'removeIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': True, u'name': u'getAppDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'type': u'constructor', u'payable': True}]

#[{u'inputs': [], u'constant': True, u'name': u'getAllIOT_Devices', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'removeApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'IP'}, {u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'registerNewIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'addAppToUser', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'constant': True, u'name': u'getAllApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': False, u'name': u'removeIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': True, u'name': u'getAppDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'type': u'constructor', u'payable': True}]

#[{u'inputs': [], u'constant': True, u'name': u'getAllIOT_Devices', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'removeApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'IP'}, {u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'registerNewIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'addAppToUser', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'constant': True, u'name': u'getAllApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': False, u'name': u'removeIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': True, u'name': u'getAppDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'type': u'constructor', u'payable': True}]

	    ########   contract_address = '0x2f0cc75a68d78590a8d06d45747ccc995af19f1b'######### PUBLIC TESTNET

	    contract_address =  '0xf057660b2f3bb519c39458844a6d23fe95071aed'  ###3 flow rules test-private blockchain

            #contract_address =  '0x2ffc914f32bcfad22525ad733da2061024a5930f' #'0x0663d9881bee70ce27e9e36f28b32d893b187d19'



            my_contract = web3.eth.contract(abi=abi, address=contract_address)
            getAllApps = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getAllApps()
            #start_time = time.time()
            #file.write(start_time)
            #print(datetime.datetime.fromtimestamp(int(start_time)).strftime('%Y-%m-%d %H:%M:%S'))            
            getAllIOT_Devices = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getAllIOT_Devices()
            apps = getAllApps.split(",")
            for i in range(0, len(apps)-1, 1):
                getAppDetails = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getAppDetails(apps[i])
                start_time = time.time()
                appdetails = getAppDetails.split(",")
                tmp = {'appIPaddr':appdetails[0], 'appName':appdetails[1], 'appURL':appdetails[2], 'appProtocol':appdetails[3], 'appPort':appdetails[4], 'time':start_time}
                apps_json1[apps[i]] = tmp
	
	    for key in apps_json1:
		server_ip = apps_json1[key]['appIPaddr']
                protocol = apps_json1[key]['appProtocol']
                port_no = apps_json1[key]['appPort']
		self.set_flow_rules_turst_list(self.datapaths[1], server_ip, protocol, port_no)
		


            devices = getAllIOT_Devices.split(",")
            for i in range(0, len(devices)-1, 1):
                getIOT_DeviceDetails = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getIOT_DeviceDetails(devices[i])
                devicedetails = getIOT_DeviceDetails.split(",")
                getIOT_DeviceApps = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getIOT_DeviceApps(devicedetails[1])
                tmp = {'IP':devicedetails[0], 'MAC':devicedetails[1], 'myApps':getIOT_DeviceApps}
                devices_json1[devices[i]] = tmp

            #print apps_json
            apps_json = apps_json1
            devices_json = devices_json1
            for key in apps_json1:
                protocol = apps_json1[key]['appProtocol']
                port_no = apps_json1[key]['appPort']
                key1 = protocol+"-"+port_no
                ports1.append(key1)

            common = list(set(ports) & set(ports1))
            remove = list(set(ports) - set(common))
            addition = list(set(ports1) - set(common))
            #print "addition:", addition
            #print "remove:", remove
            if len(addition) !=0:
                print "len(addition)", len(addition)
                for item in addition:
                    print "item in addition", item
                    print "apps_json1", apps_json1
                    for key in apps_json1:
                        #print "key:", key
                        protocol = apps_json1[key]['appProtocol']
                        port_no = apps_json1[key]['appPort']
                        print "port_no:", port_no
                        added_port = item.split("-")[1]
                        print "added_port:", added_port
                        if port_no == added_port:
                            print "port added:"
                            t = apps_json1[key]['time']
                            file.write(added_port + "," + str(t)+"\n")

                #print(datetime.datetime.fromtimestamp(int(start_time)).strftime('%Y-%m-%d %H:%M:%S'))
                #file.write(start_time)   
            ports = ports1
            #print 'printing white list'
            #print ports1
            #print apps_json
            #print devices_json

            for key in devices_json:
                src_mac = key
                scr_ip = devices_json[key]['IP']
                myapps1 = devices_json[key]['myApps'].split(",")
                #print myapps1
                if key in mac_json:
                    for i in range(0, len(myapps1)-1, 1):
                        if myapps1[i] in apps_json:
                            dst_ip = apps_json[myapps1[i]]['appIPaddr']
                            dst_port = apps_json[myapps1[i]]['appPort']
                            proto = apps_json[myapps1[i]]['appProtocol']
                            print 'src_mac, scr_ip, dst_ip, dst_port, proto', src_mac, scr_ip, dst_ip, dst_port, proto 
                            source1 = mac_json[key]['dpid']+ "-"+mac_json[key]['in_port']
                            #source1 = '1-1'
                            dest1 = server_gateway
                            print 'source1, server_gateway, src_mac, scr_ip, dst_ip, dst_port, proto:', source1, server_gateway, src_mac, scr_ip, dst_ip, dst_port, proto
                            self.create_graph_permanent(source1, server_gateway, src_mac, scr_ip, dst_ip, dst_port, proto)

            #print mac_json
            hub.sleep(1)
            #file.close()




    """@set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        msg = ev.switch.to_dict()
        print "_event_switch_enter_handler msg: ", msg
        print "_event_switch_enter_handler ev.switch.dp.address, ev.switch.dp.id: ", ev.switch.dp.address, ev.switch.dp.id
        for sw in api.get_all_switch(self):
            print "sw.dp.socket.getpeername(), sw.dp.id: ", sw.dp.socket.getpeername(), sw.dp.id


        #self._rpc_broadcall('event_switch_enter', msg)"""

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        msg = ev.switch.to_dict()
        #print "_event_switch_leave_handler msg: ", msg
        #self._rpc_broadcall('event_switch_leave', msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        global switch_links
        #msg = ev.link.to_dict()
        #print "_event_link_add_handler msg: ", msg
        #print "_event_link_add_handler msg.keys(): ", msg.keys()
        #print "_event_link_add_handler msg.values(): ", msg.values()
        #print "_event_link_add_handler ev.switch.dp.address: ", ev.switch.dp.address
        #print "msg.get('src').get('name'), msg.get('dst').get('name'): ", msg.get('src').get('name'), msg.get('dst').get('name')
        #print "msg.get('src').get('hw_addr'), msg.get('dst').get('hw_addr'): ", msg.get('src').get('hw_addr'), msg.get('dst').get('hw_addr')

        """link_src = msg.get('src').get('name').strip()
        link_dst = msg.get('dst').get('name').strip()

        dpid_src = str(int(msg.get('src').get('dpid'))).strip()
        port_no_src = str(int(msg.get('src').get('port_no'))).strip()
        hw_addr_src = msg.get('src').get('hw_addr').strip()

        dpid_dst = str(int(msg.get('dst').get('dpid'))).strip()
        port_no_dst = str(int(msg.get('dst').get('port_no'))).strip()  
        hw_addr_dst = msg.get('dst').get('hw_addr').strip()"""

        #key1.replace("'", "")
        #key1 = key1[1:]
        #key1 = key1[key1.index("'")+1:key1.rindex("'")]
        #print "key1: ", key1
        #key = (link_src + "," + link_dst)
        #key_rev = (link_dst + "," + link_src)
        #print "key : ", key
        #value = (dpid_src + "," + port_no_src + "," + hw_addr_src + "," + dpid_dst + "," + port_no_dst + "," + hw_addr_dst)
        #value = (dpid_src + "," + port_no_src + "," + hw_addr_src + "," + dpid_dst + "," + port_no_dst + "," + hw_addr_dst + "," + "" + "," + "" + "," + "" + "," + "" + "," + "" + "," + "")
        #print "value : ", value
        """if key not in switch_links and key_rev not in switch_links:
            switch_links[key] = []
            switch_links[key].append(value)"""
        #print "_event_link_add_handler: ", ev.link.src, ev.link.dst
        #print self._get_hwaddr(ev.link.src.dpid, ev.link.src.port_no)
        #self._rpc_broadcall('event_link_add', msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        msg = ev.link.to_dict()
        #print "_event_link_delete_handler msg: ", msg
        #self._rpc_broadcall('event_link_delete', msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        global flag
        msg = ev.host.to_dict()
        #print "_event_host_add_handler msg: ", msg
        """if(flag == 0):
            self.monitor_thread = hub.spawn(self._monitor)
            flag = 1"""
        #self._rpc_broadcall('event_host_add', msg)    



    def _get_hwaddr(self, dpid, port_no):
        return self.dpset.get_port(dpid, port_no).hw_addr

    
    
    
	############ flow rules to send packets matching trust list to controller for further processing ###########
    def set_flow_rules_turst_list(self, datapath, server_ip, protocol, server_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	#if protocol == 'tcp':
		#print protocol
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=('10.0.0.0', '255.255.255.0'), ipv4_dst= server_ip, ip_proto=6, tcp_dst=int(server_port))
        priority = 65510
	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
	#actions = [datapath.ofproto_parser.OFPActionOutput(port=datapath.ofproto.OFPP_CONTROLLER)]
        #actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)




    def set_flow_rules_iot_arp(self, datapath, in_port, out_port, source_IP, source_MAC, opcode):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=in_port, arp_op=1, eth_src=source_MAC)
        priority = 65500
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=out_port, arp_op=2, eth_dst=source_MAC)
        #priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)






    def set_flow_rules_iot_permanent_tcp(self, datapath, in_port, out_port, src_mac, scr_ip, dst_ip, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port, eth_src=src_mac, ipv4_src=scr_ip, ipv4_dst=dst_ip, ip_proto=6, tcp_dst=int(dst_port))
        priority = 65535
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, eth_dst=src_mac, ipv4_src=dst_ip, ipv4_dst=scr_ip, ip_proto=6)
        priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)


    def set_flow_rules_iot_permanent_udp(self, datapath, in_port, out_port, src_mac, scr_ip, dst_ip, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port, eth_src=src_mac, ipv4_src=scr_ip, ipv4_dst=dst_ip, ip_proto=17, udp_dst=int(dst_port))
        priority = 65535
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, eth_dst=src_mac, ipv4_src=dst_ip, ipv4_dst=scr_ip, ip_proto=17)
        priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)


    def set_flow_rules_iot_temporary_tcp(self, datapath, in_port, out_port, source_IP, dest_IP, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=6, tcp_dst=dst_port)
        #match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=6)
        priority = 65520
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=30, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, ipv4_src=dest_IP, ipv4_dst=source_IP, ip_proto=6, tcp_dst=src_port)
        #match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, ipv4_src=dest_IP, ipv4_dst=source_IP, ip_proto=6)
        #priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=30, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)


    def set_flow_rules_iot_temporary_udp(self, datapath, in_port, out_port, source_IP, dest_IP, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=17, udp_dst=dst_port)
        priority = 65520
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=30, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, ipv4_src=dest_IP, ipv4_dst=source_IP, ip_proto=17, udp_dst=src_port)
        #priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=30, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)



    def delete_flow_rules_iot_temporary_tcp(self, datapath, in_port, out_port, source_IP, dest_IP, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=6, tcp_dst=dst_port)
        priority = 65520
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, ipv4_src=dest_IP, ipv4_dst=source_IP, ip_proto=6, tcp_dst=src_port)
        #priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)


    def delete_flow_rules_iot_temporary_udp(self, datapath, in_port, out_port, source_IP, dest_IP, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=17, udp_dst=dst_port)
        priority = 65520
        actions = [parser.OFPActionOutput(out_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=out_port, ipv4_src=dest_IP, ipv4_dst=source_IP, ip_proto=17, udp_dst=src_port)
        #priority = 65535
        actions = [parser.OFPActionOutput(in_port, priority)]       
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, idle_timeout=10, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)




    #@set_ev_cls(igmplib.EventPacketIn, MAIN_DISPATCHER)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
 
    
        global destination,switch_links, multicast_tree, iot_range
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        #source1 = "1-1"
        dest1 = server_gateway
        src_ip = ''   
        dst_ip = ''  
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == 'ipv4':
                    #print 'IP packet:', p
                    src_ip = p.src   
                    #dst_ip = p.dst  
                    #if src_ip != '' and dst_ip != '':
                    testip = str(src_ip)
                    v = self.check_ipv4_in(testip, *iot_range)
                    if v:
                        src_ip = p.src 
                        dst_ip = p.dst
                        print 'IP packet:', p
                        '''if p.protocol_name == 'tcp':
                            #if src_ip != '' and dst_ip != '':
                            testip = str(src_ip)
                            v = self.check_ipv4_in(testip, *iot_range)
                            if v:
                                print 'TCP packet:', p
                                #print 'source port = ', p.src_port
                                #print 'destination port = ', p.dst_port
                                src_port = p.src_port
                                dst_port = p.dst_port 
                                proto = 'tcp'
                                for key in apps_json2:
                                    IP_address = apps_json2[key]['appIPaddr']
                                    protocol = apps_json2[key]['appProtocol']
                                    port_no = apps_json2[key]['appPort']
                                    print 'white List - appProtocol, appIPaddr, appPort', protocol, IP_address, port_no
                                    print 'IOT device packet details - src_ip, dst_ip, dst_port, proto', src_ip, dst_ip, dst_port, proto                   
                                    print IP_address == dst_ip
                                    print protocol == proto
                                    print port_no == str(dst_port)
                                    #self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)
                                    if (IP_address == dst_ip and protocol == proto and port_no == str(dst_port)):
                                        self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)


                        if p.protocol_name == 'udp':
                            #if src_ip != '' and dst_ip != '':
                            testip = str(src_ip)
                            v = self.check_ipv4_in(testip, *iot_range)
                            if v:            
                                print 'UDP packet:', p
                                print 'source port = ', p.src_port
                                print 'destination port = ', p.dst_port
                                src_port = p.src_port
                                dst_port = p.dst_port 
                                proto = 'udp'
                                for key in apps_json2:
                                    IP_address = apps_json2[key]['appIPaddr']
                                    protocol = apps_json2[key]['appProtocol']
                                    port_no = apps_json2[key]['appPort']
                                    print 'white List - appProtocol, appIPaddr, appPort', protocol, IP_address, port_no
                                    print 'IOT device packet details - src_ip, dst_ip, dst_port, proto', src_ip, dst_ip, dst_port, proto
                                    #self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)
                                    if (IP_address == dst_ip and protocol == proto and port_no == str(dst_port)):
                                        self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)'''





                 
                if p.protocol_name == 'arp':
                    #print p.protocol_name, p
                    #print 'source MAC = ', p.src_mac
                    #print 'source IP = ', p.src_ip
                    #print 'destination IP = ', p.dst_ip
                    #print 'arp opcode = ' , p.opcode
                    #print 'p.src_ip, p.dst_ip', p.src_ip, p.dst_ip
                    #if src_ip != '' and dst_ip != '':
                    #print 'p.src_ip1, p.dst_ip1', p.src_ip, p.dst_ip
                    testip = str(p.src_ip)
                    v = self.check_ipv4_in(testip, *iot_range)  
                    if v:
                        print 'ARP packet:', p
                        source1 = str(dpid) + "-" + str(in_port)
                        tmp = {'dpid':str(dpid), 'in_port':str(in_port), 'src_ip':str(p.src_ip)}
                        mac_json[p.src_mac] = tmp
                        #dest1 = "2-1"
                        if (p.opcode == 1) :
                            self.create_graph(source1, server_gateway, p.src_ip, p.src_mac, p.opcode)



                if p.protocol_name == 'tcp':
                    #if src_ip != '' and dst_ip != '':
                    testip = str(src_ip)
                    v = self.check_ipv4_in(testip, *iot_range)
                    if v:
                        print 'TCP packet:', p
                        #print 'source port = ', p.src_port
                        #print 'destination port = ', p.dst_port
                        source1 = str(dpid) + "-" + str(in_port)
                        src_port = p.src_port
                        dst_port = p.dst_port 
                        proto = 'tcp'
                        for key in apps_json:
                            IP_address = apps_json[key]['appIPaddr']
                            #IP_address = ''
                            protocol = apps_json[key]['appProtocol']
                            port_no = apps_json[key]['appPort']
                            print 'white List - appProtocol, appIPaddr, appPort', protocol, IP_address, port_no
                            print 'IOT device packet details - src_ip, dst_ip, dst_port, proto', src_ip, dst_ip, dst_port, proto                   
                            print IP_address == dst_ip
                            print protocol == proto
                            print port_no == str(dst_port)
                            #self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)
                            if (IP_address == dst_ip and protocol == proto and port_no == str(dst_port)):
                                self.create_graph_temporary(source1, server_gateway, src_ip, dst_ip, src_port, dst_port, proto)


                '''if p.protocol_name == 'udp':
                    #if src_ip != '' and dst_ip != '':
                    testip = str(src_ip)
                    v = self.check_ipv4_in(testip, *iot_range)
                    if v:            
                        print 'UDP packet:', p
                        print 'source port = ', p.src_port
                        print 'destination port = ', p.dst_port
                        src_port = p.src_port
                        dst_port = p.dst_port 
                        proto = 'udp'
                        for key in apps_json2:
                            IP_address = apps_json2[key]['appIPaddr']
                            protocol = apps_json2[key]['appProtocol']
                            port_no = apps_json2[key]['appPort']
                            print 'white List - appProtocol, appIPaddr, appPort', protocol, IP_address, port_no
                            print 'IOT device packet details - src_ip, dst_ip, dst_port, proto', src_ip, dst_ip, dst_port, proto
                            #self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)
                            if (IP_address == dst_ip and protocol == proto and port_no == str(dst_port)):
                                self.create_graph_temporary(source1, dest1, src_ip, dst_ip, src_port, dst_port, proto)'''








        '''ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip4_pkt:
                self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)'''
        

        
        '''self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)'''



    def convert_ipv4(self, ip):
        return tuple(int(n) for n in ip.split('.'))


    def check_ipv4_in(self, addr, start, end):
        return self.convert_ipv4(start) <= self.convert_ipv4(addr) <= self.convert_ipv4(end)




    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)


    def send_to_server(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        #print "_state_change_handler ev.datapath: ", ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                #print "_state_change_handler MAIN_DISPATCHER datapath: ", datapath
                print "_state_change_handler MAIN_DISPATCHER datapath.id: ", datapath.id
                """if ev.msg.desc.name == "s0-eth0":
                    src_dpid = "s0-eth0"
                    print "src_dpid: ", src_dpid
                elif ev.msg.desc.name == "s1-eth0":
                    dst_dpid = "s1-eth0"
                    print "dst_dpid: ", dst_dpid"""
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                #print "_state_change_handler DEAD_DISPATCHER datapath: ", datapath
                #print "_state_change_handler DEAD_DISPATCHER datapath.id: ", datapath.id
        """for dp in self.datapaths.values():
            print "dp.id: ", dp.id"""

    """@set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        global flag
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
        print "ev.port_state, flag: ", ev.port_state, flag 
        if all( [ev.port_state == 4, flag == 0] ): 
            print "INSIDE ***###: ",    
            monitor_thread = hub.spawn(self._monitor)
            flag = 1"""    




    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #Called when a switch connects.

        #Asks for port information and notifies the switch that we want to watch
        #for port status changes.
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        parser = datapath.ofproto_parser
	self.datapaths[datapath.id] = datapath

        #dp = ev.msg.datapath
        #ofp = dp.ofproto
        #parser = dp.ofproto_parser

         # Install table-miss flow entry
         #
         # We specify NO BUFFER to max_len of the output action due to
         # OVS bug. At this moment, if we specify a lesser number, eg,
         # 128, OVS will send Packet- In with invalid buffer_id and
         # Truncated packet data. In that case , we can not output packets
         # Correctly.
        match = parser.OFPMatch ()
        actions = [parser. OFPActionOutput (ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self. add_flow (datapath, 0, match, actions)
	
	if datapath.id == 1: 
		match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=('10.0.0.0', '255.255.255.0'), ip_proto=6)
        #match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, in_port=in_port,  ipv4_src=source_IP, ipv4_dst=dest_IP, ip_proto=6)
        	priority = 1
       		#actions = [parser.OFPActionOutput(out_port, priority)]       
        	inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        	mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD, priority=priority, match=match, instructions=inst)
        	datapath.send_msg(mod)   
	   

        # Send off the request to get current port descriptions
        """req = parser.OFPPortDescStatsRequest(dp, 0)
        dp.send_msg(req)

        packet_in_mask = ofp.OFPR_ACTION | ofp.OFPR_INVALID_TTL
        port_status_mask = ofp.OFPPR_ADD | ofp.OFPPR_DELETE | ofp.OFPPR_MODIFY
        flow_removed_mask = 0
        req = parser.OFPSetAsync(dp, [packet_in_mask, 0], [port_status_mask, 0],
                                 [flow_removed_mask, 0])
        dp.send_msg(req)"""

        """msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX,
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)"""



    def print_etherFrame(self, etherFrame):
        print "etherFrame.dst,etherFrame.src,etherFrame.ethertype: ",etherFrame.dst,etherFrame.src,etherFrame.ethertype
        LOG.debug("---------------------------------------")
        LOG.debug("eth_dst_address :%s"% etherFrame.dst)
        LOG.debug("eth_src_address :%s"% etherFrame.src)
        LOG.debug("eth_ethertype :0x%04x"% etherFrame.ethertype)
        LOG.debug("---------------------------------------")


    def print_arpPacket(self, arpPacket):
        LOG.debug("arp_hwtype :%d"% arpPacket.hwtype)
        LOG.debug("arp_proto :0x%04x"% arpPacket.proto)
        LOG.debug("arp_hlen :%d"% arpPacket.hlen)
        LOG.debug("arp_plen :%d"% arpPacket.plen)
        LOG.debug("arp_opcode :%d"% arpPacket.opcode)
        LOG.debug("arp_src_mac :%s"% arpPacket.src_mac)
        LOG.debug("arp_src_ip :%s"% arpPacket.src_ip)
        LOG.debug("arp_dst_mac :%s"% arpPacket.dst_mac)
        LOG.debug("arp_dst_ip :%s"% arpPacket.dst_ip)
        LOG.debug("---------------------------------------")


    def print_ipPacket(self, ipPacket):
        LOG.debug("ip_version :%d"% ipPacket.version)
        LOG.debug("ip_header_length :%d"% ipPacket.header_length)
        LOG.debug("ip_tos :%d"% ipPacket.tos)
        LOG.debug("ip_total_length :%d"% ipPacket.total_length)
        LOG.debug("ip_identification:%d"% ipPacket.identification)
        LOG.debug("ip_flags :%d"% ipPacket.flags)
        LOG.debug("ip_offset :%d"% ipPacket.offset)
        LOG.debug("ip_ttl :%d"% ipPacket.ttl)
        LOG.debug("ip_proto :%d"% ipPacket.proto)
        LOG.debug("ip_csum :%d"% ipPacket.csum)
        LOG.debug("ip_src :%s"% ipPacket.src)
        LOG.debug("ip_dst :%s"% ipPacket.dst)
        LOG.debug("---------------------------------------")


      

    def receive_ip(self, datapath, packet, etherFrame, inPort):
        ipPacket = packet.get_protocol(ipv4)
        LOG.debug("receive IP packet %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
        self.print_etherFrame(etherFrame)
        self.print_ipPacket(ipPacket)
        if ipPacket.proto == inet.IPPROTO_ICMP:
            icmpPacket = packet.get_protocol(icmp.icmp)
            self.check_icmp(datapath, etherFrame, ipPacket, icmpPacket, inPort)
            return 0
        else:
            LOG.debug("Drop packet")
            return 1

        for portNo in self.arpInfo.keys():
            if portNo == inPort:
                break
        else:
            hostIpAddr = ipPacket.src
            hostMacAddr = etherFrame.src
            self.arpInfo[inPort] = ArpTable(hostIpAddr, hostMacAddr, inPort)
        return 0



    def create_graph(self, source1, dest1, source_IP, source_MAC, opcode):
        global switch_links, multicast_tree, destination
        multicast_tree_new = {}
        multicast_tree_old = multicast_tree.copy()
        combined1 = []
        combined = []
        cpath = []
        rep = []
        g = Graph()
        if (bool(switch_links)) :
            for i in range(1, len(self.datapaths)+1):
                g.add_vertex(str(i))
            for k, val in switch_links.items():
                g.add_edge(val[0], val[3], 1)


        #print 'Graph data:'
        for v in g:
            for w in v.get_connections():
                vid = v.get_id()
                wid = w.get_id()
                #print '( %s , %s, %3d)'  % ( vid, wid, v.get_weight(w))

        #dests = ['9', '12', '6', '5']
        #dests = ['5']
        source_dpid = source1.split("-")[0]
        source_port = source1.split("-")[1]
        dest1_dpid = dest1.split("-")[0]
        dest1_port = dest1.split("-")[1]

        
        #key = destination[i]
        self.DDMC(g, g.get_vertex('1'), g.get_vertex(dest1_dpid)) 
        target = g.get_vertex(dest1_dpid)
        path = [dest1_dpid]
        self.shortest(target, path)
        print 'The shortest hop path for %s : %s' %(dest1_dpid, path[::-1])
        cpath = cpath + path[::-1]
        #print "path:", path
        arr = []
        rep = []
        for i in range(0, len(path)-1):
            for k, v in switch_links.items():
                if (all([v[0]==path[i],v[3]==path[i+1]])) or (all([v[3]==path[i],v[0]==path[i+1]])):
                    if all([v[0]==path[i],v[3]==path[i+1]]):
                        temp1 = v[0]+"-"+v[1]
                        temp2 = v[3]+"-"+v[4]
                        arr.append(temp1)
                        arr.append(temp2)
                    if all([v[3]==path[i],v[0]==path[i+1]]):
                        temp1 = v[3]+"-"+v[4]
                        temp2 = v[0]+"-"+v[1]
                        arr.append(temp1)
                        arr.append(temp2)
        srcport = []
        srcport.append(source1)            
        recport = []
        recport.append(dest1)
        key = source1 + "#" + dest1
        multicast_tree_new[key] = srcport + arr[::-1] + recport 

        print "IOT device to server path:", multicast_tree_new
        #print "multicast source (switch id, port no): {'1': '4'}"
        #print "multicast destinations (switch id, port no):", receiver
        #print "cpath:", cpath

        for key in multicast_tree_new:
            for i in range(0, len(multicast_tree_new[key])-1, 2):
                    src1 = multicast_tree_new[key][i]
                    src1_dpid = src1.split('-')[0]
                    src1_port = src1.split('-')[1]                    
                    src2 = multicast_tree_new[key][i+1]
                    src2_dpid = src2.split('-')[0]
                    src2_port = src2.split('-')[1]
                    self.set_flow_rules_iot_arp(self.datapaths[int(src1_dpid)], int(src1_port), int(src2_port), source_IP, source_MAC, opcode)
                    


                    #self.set_flow_rules_iot_arp(self.datapaths[int(src1_dpid)], int(src2_port), int(src1_port), source_IP, source_MAC, opcode)



    def create_graph_temporary(self, source1, dest1, source_IP, dest_IP, src_port, dst_port, proto):
        global switch_links, multicast_tree, destination
        multicast_tree_new = {}
        multicast_tree_old = multicast_tree.copy()
        combined1 = []
        combined = []
        cpath = []
        rep = []
        g = Graph()
        if (bool(switch_links)) :
            for i in range(1, len(self.datapaths)+1):
                g.add_vertex(str(i))
            for k, val in switch_links.items():
                g.add_edge(val[0], val[3], 1)


        #print 'Graph data:'
        for v in g:
            for w in v.get_connections():
                vid = v.get_id()
                wid = w.get_id()
                #print '( %s , %s, %3d)'  % ( vid, wid, v.get_weight(w))

        #dests = ['9', '12', '6', '5']
        #dests = ['5']
        source_dpid = source1.split("-")[0]
        source_port = source1.split("-")[1]
        dest1_dpid = dest1.split("-")[0]
        dest1_port = dest1.split("-")[1]

        
        #key = destination[i]
        self.DDMC(g, g.get_vertex('1'), g.get_vertex(dest1_dpid)) 
        target = g.get_vertex(dest1_dpid)
        path = [dest1_dpid]
        self.shortest(target, path)
        print 'The shortest hop path for %s : %s' %(dest1_dpid, path[::-1])
        cpath = cpath + path[::-1]
        #print "path:", path
        arr = []
        rep = []
        for i in range(0, len(path)-1):
            for k, v in switch_links.items():
                if (all([v[0]==path[i],v[3]==path[i+1]])) or (all([v[3]==path[i],v[0]==path[i+1]])):
                    if all([v[0]==path[i],v[3]==path[i+1]]):
                        temp1 = v[0]+"-"+v[1]
                        temp2 = v[3]+"-"+v[4]
                        arr.append(temp1)
                        arr.append(temp2)
                    if all([v[3]==path[i],v[0]==path[i+1]]):
                        temp1 = v[3]+"-"+v[4]
                        temp2 = v[0]+"-"+v[1]
                        arr.append(temp1)
                        arr.append(temp2)
        srcport = []
        srcport.append(source1)            
        recport = []
        recport.append(dest1)
        key = source1 + "#" + dest1
        multicast_tree_new[key] = srcport + arr[::-1] + recport 

        print "IOT device to server path:", multicast_tree_new
        #print "multicast source (switch id, port no): {'1': '4'}"
        #print "multicast destinations (switch id, port no):", receiver
        #print "cpath:", cpath

        for key in multicast_tree_new:
            for i in range(0, len(multicast_tree_new[key])-1, 2):
                    src1 = multicast_tree_new[key][i]
                    src1_dpid = src1.split('-')[0]
                    src1_port = src1.split('-')[1]                    
                    src2 = multicast_tree_new[key][i+1]
                    src2_dpid = src2.split('-')[0]
                    src2_port = src2.split('-')[1]
                    if (proto == 'tcp') :
                        self.set_flow_rules_iot_temporary_tcp(self.datapaths[int(src1_dpid)], int(src1_port), int(src2_port), source_IP, dest_IP, src_port, dst_port)
                    if (proto == 'udp') :
                        self.set_flow_rules_iot_temporary_udp(self.datapaths[int(src1_dpid)], int(src1_port), int(src2_port), source_IP, dest_IP, src_port, dst_port)



                    #self.set_flow_rules_iot_arp(self.datapaths[int(src1_dpid)], int(src2_port), int(src1_port), source_IP, source_MAC, opcode)



    def create_graph_permanent(self, source1, dest1, src_mac, scr_ip, dst_ip, dst_port, proto):
        global switch_links, multicast_tree, destination
        multicast_tree_new = {}
        multicast_tree_old = multicast_tree.copy()
        combined1 = []
        combined = []
        cpath = []
        rep = []
        g = Graph()
        if (bool(switch_links)) :
            for i in range(1, len(self.datapaths)+1):
                g.add_vertex(str(i))
            for k, val in switch_links.items():
                g.add_edge(val[0], val[3], 1)


        #print 'Graph data:'
        for v in g:
            for w in v.get_connections():
                vid = v.get_id()
                wid = w.get_id()
                #print '( %s , %s, %3d)'  % ( vid, wid, v.get_weight(w))

        #dests = ['9', '12', '6', '5']
        #dests = ['5']
        source_dpid = source1.split("-")[0]
        source_port = source1.split("-")[1]
        dest1_dpid = dest1.split("-")[0]
        dest1_port = dest1.split("-")[1]

        
        #key = destination[i]
        self.DDMC(g, g.get_vertex('1'), g.get_vertex(dest1_dpid)) 
        target = g.get_vertex(dest1_dpid)
        path = [dest1_dpid]
        self.shortest(target, path)
        print 'The shortest hop path for %s : %s' %(dest1_dpid, path[::-1])
        cpath = cpath + path[::-1]
        #print "path:", path
        arr = []
        rep = []
        for i in range(0, len(path)-1):
            for k, v in switch_links.items():
                if (all([v[0]==path[i],v[3]==path[i+1]])) or (all([v[3]==path[i],v[0]==path[i+1]])):
                    if all([v[0]==path[i],v[3]==path[i+1]]):
                        temp1 = v[0]+"-"+v[1]
                        temp2 = v[3]+"-"+v[4]
                        arr.append(temp1)
                        arr.append(temp2)
                    if all([v[3]==path[i],v[0]==path[i+1]]):
                        temp1 = v[3]+"-"+v[4]
                        temp2 = v[0]+"-"+v[1]
                        arr.append(temp1)
                        arr.append(temp2)
        srcport = []
        srcport.append(source1)            
        recport = []
        recport.append(dest1)
        key = source1 + "#" + dest1
        multicast_tree_new[key] = srcport + arr[::-1] + recport 

        print "IOT device to server path:", multicast_tree_new
        #print "multicast source (switch id, port no): {'1': '4'}"
        #print "multicast destinations (switch id, port no):", receiver
        #print "cpath:", cpath

        for key in multicast_tree_new:
            for i in range(0, len(multicast_tree_new[key])-1, 2):
                    src1 = multicast_tree_new[key][i]
                    src1_dpid = src1.split('-')[0]
                    src1_port = src1.split('-')[1]                    
                    src2 = multicast_tree_new[key][i+1]
                    src2_dpid = src2.split('-')[0]
                    src2_port = src2.split('-')[1]
                    if (proto == 'tcp') :
                        self.set_flow_rules_iot_permanent_tcp(self.datapaths[int(src1_dpid)], int(src1_port), int(src2_port), src_mac, scr_ip, dst_ip, dst_port)
                    if (proto == 'udp') :
                        self.set_flow_rules_iot_permanent_udp(self.datapaths[int(src1_dpid)], int(src1_port), int(src2_port), src_mac, scr_ip, dst_ip, dst_port)




    def shortest(self, v, path):
        ''' make shortest path from v.previous'''
        if v.previous:
            path.append(v.previous.get_id())
            self.shortest(v.previous, path)
        return

    #import heapq

    def DDMC(self, aGraph, start, target):
        #print '''DDMC shortest path'''
        # Set the distance for the start node to zero 
        start.set_distance(0)

        # Put tuple pair into the priority queue
        unvisited_queue = [(v.get_distance(),v) for v in aGraph]
        heapq.heapify(unvisited_queue)

        while len(unvisited_queue):
            # Pops a vertex with the smallest distance 
            uv = heapq.heappop(unvisited_queue)
            current = uv[1]
            current.set_visited()

            #for next in v.adjacent:
            for next in current.adjacent:
                # if visited, skip
                if next.visited:
                    continue
                new_dist = current.get_distance() + current.get_weight(next)
                
                if new_dist < next.get_distance():
                    next.set_distance(new_dist)
                    next.set_previous(current)
                    """print 'updated : current = %s next = %s new_dist = %s' \
                            %(current.get_id(), next.get_id(), next.get_distance())"""
                else:
                    """print 'not updated : current = %s next = %s new_dist = %s' \
                            %(current.get_id(), next.get_id(), next.get_distance())"""

            # Rebuild heap
            # 1. Pop every item
            while len(unvisited_queue):
                heapq.heappop(unvisited_queue)
            # 2. Put all vertices not visited into the queue
            unvisited_queue = [(v.get_distance(),v) for v in aGraph if not v.visited]
            heapq.heapify(unvisited_queue)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global switch_links
        #msg = ev.switch.to_dict()
        #print "get_topology_data msg: ", msg
        #switch_list = get_switch(self.topology_api_app, None)  
        #switches=[switch.dp.id for switch in switch_list]
        #self.net.add_nodes_from(switches)       
        """print "**********List of switches"
        for switch in switch_list:
          #self.ls(switch)
          print switch
          #self.nodes[self.no_of_nodes] = switch
          #self.no_of_nodes += 1"""
       
        links_list = get_link(self.topology_api_app, None)
        print "links_list: ",links_list
        #links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #links=[(link.src.name,link.src.dpid,link.src.port_no,link.src.hw_addr,link.dst.name,link.dst.dpid,link.dst.port_no,link.dst.hw_addr) for link in links_list]
        
        #print "links1: ",links
        for link in links_list:
            

            link_src = link.src.name.strip()
            link_dst = link.dst.name.strip()
            #print "link:", link_src,"--",link_dst
            #if(link_src.startswith("u")):


            dpid_src = str(int(link.src.dpid)).strip()
            port_no_src = str(int(link.src.port_no)).strip()
            hw_addr_src = link.src.hw_addr.strip()

            dpid_dst = str(int(link.dst.dpid)).strip()
            port_no_dst = str(int(link.dst.port_no)).strip()  
            hw_addr_dst = link.dst.hw_addr.strip()

            #print "link_src,link_dst: ", link_src, link_dst

            """print "dpid_src: ", dpid_src
            print "port_no_src: ", port_no_src
            print "hw_addr_src: ", hw_addr_src

            print "dpid_dst: ", dpid_dst
            print "port_no_dst: ", port_no_dst
            print "hw_addr_dst: ", hw_addr_dst"""



            key = (link_src + "," + link_dst)
            key_rev = (link_dst + "," + link_src)
            #print "key, key_rev: ", key, key_rev
            
            value = (dpid_src + "," + port_no_src + "," + hw_addr_src + "," + dpid_dst + "," + port_no_dst + "," + hw_addr_dst)
            if all( [key not in switch_links, key_rev not in switch_links] ):  
                print "link:", link_src,"--",link_dst
                #list_of_links=get_link(self,dpid=dpid_src)
                #print "list_of_links for : ",dpid_src,"-",list_of_links

                strs = ["0" for x in range(6)]  
                #switch_links[key] = strs
                #switch_links[key] = []
                #print(strs)
                #global s
                strs[0] = dpid_src
                strs[1] = port_no_src
                strs[2] = hw_addr_src
                strs[3] = dpid_dst
                strs[4] = port_no_dst
                strs[5] = hw_addr_dst
                #num = int(s, 16) + 1
                #s = str(hex(num)[2:])
                #hnum = hex(num)[2:].upper()
                #hnum = hex(num)[2:].lower()
                #print "hnum:", hnum
                #s1 = str(hnum)
                #sd = s1[0:2]+":"+s1[2:4]+":"+s1[4:6]+":"+s1[6:8]+":"+s1[8:10]+":"+s1[10:12]
                #print "num: ", sd
                #strs[13] = s1[0:2]+":"+s1[2:4]+":"+s1[4:6]+":"+s1[6:8]+":"+s1[8:10]+":"+s1[10:12]--------------

                switch_links[key] = strs
                #print(strs)
                #v = v+1
                #switch_links[key].append(strs)
                #print(switch_links[key])   
        #print switch_links   
        #self.monitor_thread = hub.spawn(self._monitor)
        #self.net.add_edges_from(links)
        #links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print "links2: ",links
        #self.net.add_edges_from(links)
        #print "**********List of links"
        #print self.net.edges()





#app_manager.require_app('ryu.app.rest_topology')
#app_manager.require_app('ryu.app.ws_topology')
#app_manager.require_app('ryu.app.ofctl_rest')
