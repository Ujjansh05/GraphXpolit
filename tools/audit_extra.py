"""Additional bounded local probes for idle CPU and dashboard security."""
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
import ctypes
from ctypes import wintypes
from audit_runtime import EXE, ROOT, kernel, memory

kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)]*4
def cpu(handle):
    ts = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in ts]): raise ctypes.WinError()
    return sum((t.dwHighDateTime << 32) + t.dwLowDateTime for t in ts[2:])/10**7

def main():
    result={}
    with tempfile.TemporaryDirectory(prefix='graphxploit-extra-') as temp:
        root=Path(temp); project=root/'project'; project.mkdir()
        for i in range(100): (project/f'm{i}.py').write_text(f'def f{i}():\n    return 1\n')
        env=dict(os.environ,GRAPHXPLOIT_DATA_DIR=str(root/'data'))
        with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        # An argument is rendered into HTML without any filesystem access.
        payload='</script><script>window.AUDIT_MARKER=1</script>'
        server=subprocess.Popen([str(EXE),'serve',payload,'--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        handle=kernel.OpenProcess(0x410,False,server.pid)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def req(path='/', body=None, headers=None):
            r=urllib.request.Request(f'http://127.0.0.1:{port}{path}',data=json.dumps(body).encode() if body is not None else None,headers=headers or {})
            try:
                with opener.open(r,timeout=15) as response: return response.status,response.read().decode()
            except urllib.error.HTTPError as e: return e.code,e.read().decode()
        try:
            for _ in range(100):
                try: _,html=req(); break
                except urllib.error.URLError: time.sleep(.05)
            token=re.search(r'GRAPHXPLOIT_TOKEN = "([^"]+)"',html).group(1)
            auth={'Content-Type':'application/json','X-GraphXploit-Token':token}
            start=cpu(handle); time.sleep(5)
            result['idle']={'seconds':5,'cpu_seconds':round(cpu(handle)-start,5),'working_set_mib':round(memory(handle).ws/2**20,2)}
            result['unescaped_script_in_bootstrap']=payload in html
            status,html2=req(headers={'Host':'attacker.invalid'})
            result['foreign_host_can_read_bootstrap_token']=status==200 and token in html2
            jobs=[]
            for _ in range(4):
                status,body=req('/api/v1/scan',{'root':str(project)},auth)
                jobs.append({'http':status,**json.loads(body)})
            result['four_scan_requests']=jobs
            cancel_start=time.perf_counter()
            for job in jobs:
                if 'id' in job: req('/api/v1/jobs/'+job['id']+'/cancel',{},auth)
            statuses=[]
            for job in jobs:
                if 'id' not in job: continue
                for _ in range(200):
                    _,body=req('/api/v1/jobs/'+job['id'],headers=auth)
                    data=json.loads(body)
                    if data['status']!='running': break
                    time.sleep(.05)
                statuses.append(data)
            result['cancel_seconds']=round(time.perf_counter()-cancel_start,3)
            result['cancel_outcomes']=statuses
            result['oversized_json_status']=req('/api/v1/scan',{'root':'x'*(3*1024*1024)},auth)[0]
        finally:
            server.terminate(); server.wait(timeout=10); kernel.CloseHandle(handle)
    (ROOT/'audit-extra.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
