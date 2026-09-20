"""Query OSV for public registry package names/versions in Cargo.lock."""
import json
from pathlib import Path
import tomllib
import urllib.request

root = Path(__file__).resolve().parents[1]
packages = [p for p in tomllib.loads((root/'Cargo.lock').read_text())['package'] if p.get('source','').startswith('registry+')]
results = []
for offset in range(0, len(packages), 100):
    batch = packages[offset:offset+100]
    payload = {'queries': [{'package': {'name': p['name'], 'ecosystem':'crates.io'}, 'version':p['version']} for p in batch]}
    req = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=60) as response:
        data = json.load(response)
    for p, result in zip(batch, data['results']):
        if result.get('vulns'):
            results.append({'package':p['name'],'version':p['version'],'advisories':result['vulns']})
report = {'source':'https://api.osv.dev/v1/querybatch','registry_packages_checked':len(packages),'scope':'entire Cargo.lock including optional and development dependencies; no claim about reachability','matches':results}
(root/'audit-dependencies.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
