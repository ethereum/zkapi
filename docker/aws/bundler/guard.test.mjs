import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validateRequest} from './guard.mjs';
const pins={paymaster:'0x'+'11'.repeat(20),factory:'0x'+'22'.repeat(20)};
const op={sender:'0x'+'33'.repeat(20),paymaster:pins.paymaster,factory:pins.factory};
const request={jsonrpc:'2.0',id:1,method:'eth_sendUserOperation',params:[op,'0x0000000071727De22E5E9d8BAf0edAc6f37da032']};
test('only fixed Sepolia contracts and public methods reach the bundler',()=>{
    assert.equal(validateRequest(request,pins),null);
    assert.equal(validateRequest({...request,params:[{...op,factory:undefined},request.params[1]]},pins),null);
    for(const field of ['paymaster','factory'])assert.ok(validateRequest({...request,params:[{...op,[field]:'0x'+'44'.repeat(20)},request.params[1]]},pins));
    assert.ok(validateRequest({...request,params:[op,'0x'+'44'.repeat(20)]},pins));
    for(const method of ['debug_bundler_clearState','eth_sendRawTransaction','eth_call','pimlico_sendUserOperationNow'])assert.ok(validateRequest({...request,method},pins));
    assert.ok(validateRequest([request],pins));
});
test('state overrides and alternate operation formats are rejected',()=>{
    assert.ok(validateRequest({...request,params:[...request.params,{}]},pins));
    for(const field of ['initCode','paymasterAndData','eip7702Auth','authorizationList'])assert.ok(validateRequest({...request,params:[{...op,[field]:'0x'},request.params[1]]},pins));
});
test('read methods validate parameters',()=>{
    assert.equal(validateRequest({...request,method:'eth_chainId',params:[]},pins),null);
    assert.equal(validateRequest({...request,method:'eth_getUserOperationReceipt',params:['0x'+'55'.repeat(32)]},pins),null);
    assert.ok(validateRequest({...request,method:'eth_getUserOperationReceipt',params:[]},pins));
    assert.ok(validateRequest({...request,method:'eth_chainId',params:[{}]},pins));
});
