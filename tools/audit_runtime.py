"""Isolated Windows runtime audit; fixtures are generated, never user projects."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / 'target/release/graphxploit.exe'
class Memory(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [(x, ctypes.c_size_t) for x in ['peak_ws', 'ws', 'peak_pool', 'pool', 'peak_nonpool', 'nonpool', 'pagefile', 'peak_pagefile']]
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
def memory(handle):
    m = Memory(); m.cb = ctypes.sizeof(m)
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(m), m.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return m

def run(args, env):
    start = time.perf_counter()
    # Files prevent pipe deadlock on large JSON output.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen([str(EXE), *map(str, args)], env=env, stdout=out, stderr=err)
        handle = kernel.OpenProcess(0x410, False, p.pid)
        peak = 0
        try:
            while p.poll() is None:
                peak = max(peak, memory(handle).peak_ws)
                if time.perf_counter() - start > 120:
                    p.kill(); p.wait(); raise TimeoutError(args)
                time.sleep(.005)
            peak = max(peak, memory(handle).peak_ws)
        finally:
            kernel.CloseHandle(handle)
        out.seek(0); err.seek(0)
        return {'seconds': round(time.perf_counter()-start, 4), 'peak_working_set_mib': round(peak/2**20, 2), 'exit': p.returncode, 'stdout': out.read().decode(errors='replace'), 'stderr': err.read().decode(errors='replace')}

def main():
    report = {'binary_bytes': EXE.stat().st_size, 'method': 'Windows process peak working set; synthetic Python fixtures; one run per condition; warm OS cache possible; browser excluded', 'benchmarks': [], 'security': {}}
    with tempfile.TemporaryDirectory(prefix='graphxploit-audit-') as temp:
        base = Path(temp)
        env = dict(os.environ, GRAPHXPLOIT_DATA_DIR=str(base/'data'))
        for count in [100, 1000, 5000]:
            project = base/f'project-{count}'; project.mkdir()
            for i in range(count):
                text = ''.join(f'def f_{i}_{j}():\n    return f_{i}_{j+1}()\n\n' for j in range(19)) + f'def f_{i}_19():\n    return 1\n'
                (project/f'm{i}.py').write_text(text)
            for phase in ['initial', 'unchanged', 'one-file-change']:
                if phase == 'one-file-change':
                    with (project/'m0.py').open('a') as f: f.write('\ndef new_function():\n    return 2\n')
                row = run(['scan', project], env)
                row.update(files=count, phase=phase)
                report['benchmarks'].append(row)
                print(count, phase, row['seconds'], row['peak_working_set_mib'], flush=True)
            row = run(['impact', project, 'f_0_19', '--json'], env)
            parsed = json.loads(row.pop('stdout'))
            row.update(files=count, phase='impact', results=len(parsed['results']))
            report['benchmarks'].append(row)
        report['total_index_bytes_three_projects'] = sum(p.stat().st_size for p in (base/'data').rglob('*') if p.is_file())
        report['index_files'] = [p.stat().st_size for p in (base/'data').rglob('*.db')]
        fan = base/'fan'; fan.mkdir()
        (fan/'wide.py').write_text('def target():\n    return 1\n'+''.join(f'def caller_{i}():\n    return target()\n' for i in range(600)))
        run(['scan', fan], env)
        query = json.loads(run(['impact', fan, 'target', '--json'], env)['stdout'])
        report['security']['result_limit'] = {'returned': len(query['results']), 'configured_limit': 500, 'complete': query['complete']}
        for endpoint in ['http://localhost.attacker.invalid', 'http://127.0.0.1.attacker.invalid', 'http://example.invalid']:
            result = run(['model','configure','ollama',endpoint,'test-model'], env)
            report['security'][endpoint] = {'accepted': result['exit']==0}
        (base/'outside.txt').write_text('SYNTHETIC_OUTSIDE_SECRET')
        (fan/'large.txt').write_text('A'* (4*1024*1024))
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        server = subprocess.Popen([str(EXE),'serve',str(fan),'--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        handle = kernel.OpenProcess(0x410, False, server.pid)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(path='/', body=None, headers=None, method=None):
            req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=json.dumps(body).encode() if body is not None else None, headers=headers or {}, method=method)
            try:
                with opener.open(req,timeout=15) as r: return r.status,dict(r.headers),r.read().decode()
            except urllib.error.HTTPError as e: return e.code,dict(e.headers),e.read().decode()
        try:
            for _ in range(100):
                try: status, headers, html=request(); break
                except urllib.error.URLError: time.sleep(.05)
            token=re.search(r'GRAPHXPLOIT_TOKEN = "([^"]+)"',html).group(1)
            auth={'Content-Type':'application/json','X-GraphXploit-Token':token}
            body={'root':str(fan),'path':'wide.py','start_line':1,'end_line':5}
            sec=report['security']
            sec['no_token_status']=request('/api/v1/source',body,{'Content-Type':'application/json'})[0]
            sec['wrong_token_status']=request('/api/v1/source',body,dict(auth, **{'X-GraphXploit-Token':'wrong'}))[0]
            sec['valid_token_status']=request('/api/v1/source',body,auth)[0]
            outside=dict(body,path='../outside.txt')
            sec['path_escape_status']=request('/api/v1/source',outside,auth)[0]
            status,_,data=request('/api/v1/source',dict(body,path=str(base/'outside.txt')),auth)
            sec['absolute_path_escape_status']=status
            status,_,data=request('/api/v1/source',dict(body,root=str(base),path='outside.txt'),auth)
            sec['request_can_change_root']={'status':status,'synthetic_secret_returned':'SYNTHETIC_OUTSIDE_SECRET' in data}
            status,_,data=request('/api/v1/source',dict(body,path='large.txt'),auth)
            sec['large_source_read']={'status':status,'response_bytes':len(data.encode())}
            sec['host_header_status']=request(headers={'Host':'attacker.invalid'})[0]
            sec['foreign_origin_status']=request(headers={'Origin':'https://attacker.invalid'})[0]
            sec['cors_preflight_status']=request('/api/v1/source',headers={'Origin':'https://attacker.invalid','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'x-graphxploit-token'},method='OPTIONS')[0]
            sec['response_security_headers']={k:v for k,v in headers.items() if k.lower() in ['content-security-policy','x-frame-options','x-content-type-options','access-control-allow-origin']}
            sec['server_working_set_mib_after_requests']=round(memory(handle).ws/2**20,2)
        finally:
            server.terminate(); server.wait(timeout=10); kernel.CloseHandle(handle)
    output=ROOT/'audit-results.json'
    output.write_text(json.dumps(report,indent=2))
    print(output)

if __name__ == '__main__': main()
