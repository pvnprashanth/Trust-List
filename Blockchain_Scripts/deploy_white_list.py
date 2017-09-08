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

#web3 = Web3(IPCProvider())
web3 = Web3(IPCProvider('/home/prashanth/.ethereum/testnet/geth.ipc'))
#obj = web3.Web3(web3.HTTPProvider('http://192.168.233.133:8111'))
#psn = web3.personal.Personal(obj)
web3.personal.unlockAccount(web3.eth.accounts[0],"prashanth",1000) #replace 123456 to your Ethereum accounts password


#source_code = 'contract MyToken { address issuer; mapping (address => uint) balances; event Issue(address account, uint amount); event Transfer(address from, address to, uint amount); function MyToken() { issuer = msg.sender; } function issue(address account, uint amount) { if (msg.sender != issuer) throw; balances[account] += amount; } function transfer(address to, uint amount) { if (balances[msg.sender] < amount) throw; balances[msg.sender] -= amount; balances[to] += amount; Transfer(msg.sender, to, amount); } function getBalance(address account) constant returns (uint) { return balances[account]; } }'

source_code = 'contract WhiteList { address WhiteListAdmin; mapping ( bytes32 => notarizedApp) notarizedApps; bytes32[] appsByNotaryHash; string[] appsByName; mapping ( bytes32 => IOT_Device ) IOT_Devices; string[] IOT_DevicesByMAC; struct notarizedApp { string appIPaddr; string appName; string appURL; string appProtocol; string appPort; } struct IOT_Device { string IP; string MAC; string[] myApps; } function WhiteList() payable { WhiteListAdmin = msg.sender; } modifier onlyAdmin() { if (msg.sender != WhiteListAdmin) throw; _; } function removeIOT_Device(string MAC) onlyAdmin returns (bool success) { bytes32 key = keccak256(MAC); delete IOT_Devices[key]; return true; } function removeApp(string appName) onlyAdmin returns (bool success) { bytes32 key = keccak256(appName); delete notarizedApps[key]; return true; } function registerNewIOT_Device(string IP, string MAC, string appName) onlyAdmin returns (bool success) { bytes32 key = keccak256(MAC); if(bytes(MAC).length != 0 && bytes(appName).length != 0){ if(bytes(IOT_Devices[key].MAC).length == 0) { IOT_Devices[key].IP = IP; IOT_Devices[key].MAC = MAC; IOT_Devices[key].myApps.push(appName); IOT_DevicesByMAC.push(MAC); return true; }else { IOT_Devices[key].myApps.push(appName); return true; } } else { return false; } } function registerNewApp(string appIPaddr, string appName, string appURL, string appProtocol, string appPort) onlyAdmin returns (bool success) { bytes32 key = keccak256(appName); if(bytes(notarizedApps[key].appName).length == 0 && bytes(appName).length != 0){ notarizedApps[key].appIPaddr = appIPaddr; notarizedApps[key].appName = appName; notarizedApps[key].appURL = appURL; notarizedApps[key].appProtocol = appProtocol; notarizedApps[key].appPort = appPort; appsByNotaryHash.push(key); appsByName.push(appName); return true; } else { return false; } } function addAppToUser(string MAC, string appIPaddr, string appName, string appURL, string appProtocol, string appPort) onlyAdmin returns (bool success) { bytes32 key = keccak256(MAC); bytes32 key1 = keccak256(appName); if(bytes(IOT_Devices[key].MAC).length != 0){ if(bytes(appName).length != 0){ if(bytes(notarizedApps[key1].appName).length == 0) { appsByNotaryHash.push(key1); } notarizedApps[key1].appIPaddr = appIPaddr; notarizedApps[key1].appName = appName; notarizedApps[key1].appURL = appURL; notarizedApps[key1].appProtocol = appProtocol; notarizedApps[key1].appPort = appPort; IOT_Devices[key].myApps.push(appName); return true; } else { return false; } return true; } else { return false; } } function getIOT_DeviceDetails(string MAC) constant returns (string) { bytes32 key = keccak256(MAC); string memory a = IOT_Devices[key].IP; string memory b = IOT_Devices[key].MAC; string memory tmp = ","; string memory finalstring = strConcat(a,tmp,b); return finalstring; } function getIOT_DeviceApps(string MAC) constant returns (string) { bytes32 key = keccak256(MAC); string memory items; uint length = IOT_Devices[key].myApps.length; for (uint i = 0; i < length; i++) { string memory item1 = IOT_Devices[key].myApps[i]; string memory item3 = ","; items = strConcat(items, item1, item3); } return items; } function getAllApps() constant returns (string) { string memory items; uint length = appsByName.length; for (uint i = 0; i < length; i++) { string memory item1 = appsByName[i]; string memory item3 = ","; items = strConcat(items, item1, item3); } return items; } function getAllIOT_Devices() constant returns (string) { string memory items; uint length = IOT_DevicesByMAC.length; for (uint i = 0; i < length; i++) { string memory item1 = IOT_DevicesByMAC[i]; string memory item3 = ","; items = strConcat(items, item1, item3); } return items; } function getAppDetails(string appName) constant returns (string) { bytes32 key = keccak256(appName); string memory a = notarizedApps[key].appIPaddr; string memory b = notarizedApps[key].appName; string memory c = notarizedApps[key].appURL; string memory d = notarizedApps[key].appProtocol; string memory e = notarizedApps[key].appPort; string memory tmp = ","; string memory finalstring = strConcat(strConcat(a,tmp,b), strConcat(tmp,c,tmp), strConcat(d,tmp,e)); return finalstring; } function strConcat(string a, string b, string c) internal returns (string) { return strConcat1(a, b, c); } function strConcat1(string a, string b, string c) internal returns (string){ bytes memory ba = bytes(a); bytes memory bb = bytes(b); bytes memory bc = bytes(c); string memory result1 = new string(ba.length + bb.length + bc.length); bytes memory result = bytes(result1); uint k = 0; for (uint i = 0; i < ba.length; i++) result[k++] = ba[i]; for (i = 0; i < bb.length; i++) result[k++] = bb[i]; for (i = 0; i < bc.length; i++) result[k++] = bc[i]; return string(result); } }'

#web3 = Web3(Web3.HTTPProvider('http://192.168.233.133:8111'))
#web3.personal.unlockAccount(web3.eth.accounts[0],"saurabh1",1000)


compile_sol = compile_source(source_code)
#print('compile_sol: ' + str(compile_sol))
# If an `address` is not passed into this method it returns a contract factory class.

abi = compile_sol['<stdin>:WhiteList']['abi']
bytecode = compile_sol['<stdin>:WhiteList']['bin']
bytecode_runtime = compile_sol['<stdin>:WhiteList']['bin-runtime']

print('abi: ' + str(abi))
#print('bytecode: ' + str(bytecode))
#print('bytecode_runtime: ' + str(bytecode_runtime))

MyContract = web3.eth.contract(abi = abi, bytecode = bytecode, bytecode_runtime = bytecode_runtime)
#print('MyContract: ' + str(MyContract))

'''MyContract = web3.eth.contract(
    abi = compile_sol['<stdin>:MyToken']['abi'],
    bytecode = compile_sol['<stdin>:MyToken']['bin'],   # The keyword `code` has been deprecated.  You should use `bytecode` instead.
    bytecode_runtime = compile_sol['<stdin>:MyToken']['bin-runtime']  # the keyword `code_runtime` has been deprecated.  You should use `bytecode_runtime` instead.
)'''

#print('MyContract: ' + str(MyContract))

#trans_hash = MyContract.deploy(transaction={'from':web3.eth.accounts[0],'value':120})

trans_hash = MyContract.deploy(transaction={'from':web3.eth.accounts[0]})
print('trans_hash: ' + str(trans_hash))

trans_receipt = web3.eth.getTransactionReceipt(trans_hash)
#print('trans_receipt: ' + str(trans_receipt))

while (trans_receipt == None):
   trans_receipt = web3.eth.getTransactionReceipt(trans_hash)

print('trans_receipt: ' + str(trans_receipt))
contract_address = trans_receipt['contractAddress']
print('contract_address: ' + str(contract_address))

my_contract = MyContract('contractAddress')
#print('my_contract: ' + str(my_contract))

