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

web3 = Web3(IPCProvider())
#obj = web3.Web3(web3.HTTPProvider('http://192.168.233.133:8111'))
#psn = web3.personal.Personal(obj)
web3.personal.unlockAccount(web3.eth.accounts[0],"prashanth",1000) #replace 123456 to your Ethereum accounts password


abi = [{u'inputs': [], u'constant': True, u'name': u'getAllIOT_Devices', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'removeApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'IP'}, {u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appName'}], u'constant': False, u'name': u'registerNewIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}, {u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'addAppToUser', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': True, u'name': u'getIOT_DeviceApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'constant': True, u'name': u'getAllApps', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'MAC'}], u'constant': False, u'name': u'removeIOT_Device', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appName'}], u'constant': True, u'name': u'getAppDetails', u'outputs': [{u'type': u'string', u'name': u''}], u'payable': False, u'type': u'function'}, {u'inputs': [{u'type': u'string', u'name': u'appIPaddr'}, {u'type': u'string', u'name': u'appName'}, {u'type': u'string', u'name': u'appURL'}, {u'type': u'string', u'name': u'appProtocol'}, {u'type': u'string', u'name': u'appPort'}], u'constant': False, u'name': u'registerNewApp', u'outputs': [{u'type': u'bool', u'name': u'success'}], u'payable': False, u'type': u'function'}, {u'inputs': [], u'type': u'constructor', u'payable': True}]

contract_address = '0xf057660b2f3bb519c39458844a6d23fe95071aed'




my_contract = web3.eth.contract(abi=abi, address=contract_address)


getAllApps = my_contract.call({'from': web3.eth.coinbase, 'to': contract_address}).getAllApps()

print("registered apps: " + getAllApps)


