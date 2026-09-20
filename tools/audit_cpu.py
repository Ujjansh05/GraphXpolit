"""Measure process CPU time and peak memory for a bounded generated workload."""
import json
import os
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from audit_runtime import EXE, ROOT, kernel, memory
from audit_extra import cpu

results=[]
with tempfile.TemporaryDirectory(prefix='graphxploit-cpu-') as temp:
    base=Path(temp); project=base/'project'; project.mkdir()
    env=dict(os.environ,GRAPHXPLOIT_DATA_DIR=str(base/'data'))
    for i in range(1000):
        text=''.join(f'def f_{i}_{j}():\n    return f_{i}_{j+1}()\n\n' for j in range(19))+f'def f_{i}_19():\n    return 1\n'
        (project/f'm{i}.py').write_text(text)
    for phase in ['initial','unchanged']:
        start=time.perf_counter()
        p=subprocess.Popen([str(EXE),'scan',str(project)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        handle=kernel.OpenProcess(0x410,False,p.pid)
        try:
            while p.poll() is None:
                if time.perf_counter()-start>120: p.kill();p.wait();raise TimeoutError()
                time.sleep(.01)
            elapsed=time.perf_counter()-start
            seconds=cpu(handle)
            results.append({'files':1000,'phase':phase,'wall_seconds':round(elapsed,3),'cpu_seconds':round(seconds,3),'average_core_equivalents':round(seconds/elapsed,3),'peak_working_set_mib':round(memory(handle).peak_ws/2**20,2),'exit':p.returncode})
        finally: kernel.CloseHandle(handle)
    archive=base/'graphxploit.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z: z.write(EXE,EXE.name)
    report={'cpu_measurements':results,'windows_zip_bytes':archive.stat().st_size,'1000_file_index_bytes':sum(p.stat().st_size for p in (base/'data').rglob('*') if p.is_file()),'method':'CPU seconds are kernel plus user process time; average_core_equivalents=CPU/wall; single run per phase; ZIP uses Python deflate defaults'}
    (ROOT/'audit-cpu.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
