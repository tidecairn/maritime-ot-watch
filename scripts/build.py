#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,shutil
R=Path(__file__).resolve().parents[1]; D=R/'dist'
if D.exists(): shutil.rmtree(D)
D.mkdir()
files=['index.html','methodology.html','privacy.html','404.html','robots.txt','assets/watch.css','assets/watch.js','assets/favicon.svg','data/watch.json','data/watch.sha256']
for p in files:
 s=R/p;t=D/p;t.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(s,t)
json.loads((D/'data/watch.json').read_text())
expected=(D/'data/watch.sha256').read_text().split()[0]; actual=hashlib.sha256((D/'data/watch.json').read_bytes()).hexdigest(); assert expected==actual
rows=[f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(D).as_posix()}" for p in sorted(D.rglob('*')) if p.is_file()]
(D/'SHA256SUMS.txt').write_text('\n'.join(rows)+'\n')
print('PASS: static distribution built; files=',len(rows))
