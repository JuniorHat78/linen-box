"""Read an opaque worker export without trusting ZIP paths or extra files."""
from pathlib import Path
import re
import shutil
import stat
import zipfile

from sealed import MAX_BYTES


def extract_export(archive, destination, stem, kind):
    if not re.fullmatch(r'result-\d{3}-\d+-\d+', stem) or kind not in ('index', 'full'):
        raise ValueError('Invalid export identity')
    receipt = stem + '.json'
    boxes = {stem + '.box'} | ({stem + '-index.box'} if kind == 'index' else set())
    with zipfile.ZipFile(archive) as zipped:
        members = zipped.infolist()
        names = [m.filename for m in members]
        if (len(members) != 2 or len(set(names)) != 2 or receipt not in names
                or len(set(names) & boxes) != 1
                or any(n not in boxes | {receipt} for n in names)):
            raise ValueError('Unexpected export inventory')
        if any(m.is_dir() or stat.S_ISLNK(m.external_attr >> 16) or m.file_size > MAX_BYTES + 64
               or (m.filename == receipt and m.file_size > 16384) for m in members):
            raise ValueError('Unsafe export member')
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        for member in members:
            target = destination / member.filename
            temporary = target.with_name(target.name + '.partial')
            with zipped.open(member) as source, temporary.open('wb') as output:
                shutil.copyfileobj(source, output, 1024**2)
            temporary.replace(target)
    return destination / receipt
