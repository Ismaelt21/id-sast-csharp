import json
from core.parsers.ast_importer import AstImporter

with open('C:/Temp/bridge_raw2.json', encoding='utf-8-sig') as f:
    raw = json.load(f)

model = AstImporter().import_from_dict(raw)

for cls in model.classes:
    for method in cls.methods:
        if method.name != 'GetProduct' or 'Fixed' not in cls.name:
            continue
        for sn in model.nodes_by_method.get(method.method_id, []):
            print(f'line={sn.line:3} sink={str(sn.is_known_sink):5} san={str(sn.is_known_sanitizer):5} sym={sn.resolved_symbol}')
