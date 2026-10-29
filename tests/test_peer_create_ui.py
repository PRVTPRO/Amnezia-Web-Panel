"""Execute the real submit handler through a timeout and retry."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


class CreateOperationUI(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'node is required')
    def test_timeout_reuses_operation_and_success_starts_new_intent(self):
        source = (Path(__file__).resolve().parents[1] / 'templates/users.html').read_text(encoding='utf-8')
        function = 'async function doAddUserConnection()' + source.split(
            'async function doAddUserConnection()', 1)[1].split('\n    // var on purpose:', 1)[0]
        script = r'''
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto').webcrypto;
const values = {ucMode:'new',ucServer:'0',ucProtocol:'awg3',ucName:'device'};
const fields = Object.fromEntries(Object.entries(values).map(([id,value])=>[id,{value}]));
for (const id of ['ucAddBtn','ucAddBtnText','ucAddSpinner']) fields[id]={classList:{remove(){},add(){}}};
const saved = new Map();
const storage = {getItem:k=>saved.get(k)||null,setItem:(k,v)=>saved.set(k,v),removeItem:k=>saved.delete(k)};
const calls=[];
const ctx=vm.createContext({crypto,Uint8Array,console,currentUserId:'u',
 document:{getElementById:id=>fields[id]},sessionStorage:storage,localStorage:{setItem(){}},
 _:x=>x,showToast(){},closeModal(){},refreshUsersList(){},
 apiCall:async(url,method,body)=>{calls.push({...body});if(calls.length===1)throw Error('timeout');return {};}});
vm.runInContext(FUNCTION,ctx);
(async()=>{
 await vm.runInContext('doAddUserConnection()',ctx);
 assert.equal(calls.length,1);
 // Re-evaluate the real handler, retaining storage as a page reload would.
 vm.runInContext(FUNCTION,ctx);
 await vm.runInContext('doAddUserConnection()',ctx);
 await vm.runInContext('doAddUserConnection()',ctx);
 assert.match(calls[0].operation_id,/^[a-f0-9-]{36}$/);
 assert.equal(calls[0].operation_id,calls[1].operation_id);
 assert.notEqual(calls[1].operation_id,calls[2].operation_id);
 console.log('PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''.replace('FUNCTION', json.dumps(function))
        result = subprocess.run([shutil.which('node'), '-e', script], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS', result.stdout)
