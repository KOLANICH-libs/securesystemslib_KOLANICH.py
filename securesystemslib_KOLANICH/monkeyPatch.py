import ast
from pathlib import Path

import securesystemslib.ecdsa_keys

__license__ = "Unlicense"


def modifyKeyIdComputingAST(f):
	for el in f.body:
		if isinstance(el, ast.Assign):
			ts = el.targets
			if len(ts) == 1 and isinstance(ts[0], ast.Name) and ts[0].id == "public":
				v = el.value
				if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "public_bytes":
					el.value = ast.Call(func=ast.Attribute(value=v, attr="strip", ctx=ast.Load()), args=[], keywords=[])
					return f


def modifyPemImportingFuncInModule(f, funcToMonkeyPatch: str):
	for el in f.body:
		if isinstance(el, ast.FunctionDef) and el.name == funcToMonkeyPatch:
			res = modifyKeyIdComputingAST(el)
			if res is not None:
				return res


def monkeyPatchFuncInModule(module, funcToMonkeyPatch: str):
	d = Path(module.__file__)
	f = ast.parse(d.read_text())
	modifiedFunc = modifyPemImportingFuncInModule(f, funcToMonkeyPatch)
	monkeyPatchModule = ast.fix_missing_locations(ast.Module(body=[modifiedFunc], type_ignores=[]))
	exec(compile(monkeyPatchModule, "<monkey-patch of " + funcToMonkeyPatch + ">", "exec"), module.__dict__)


monkeyPatchFuncInModule(securesystemslib.ecdsa_keys, "create_ecdsa_public_and_private_from_pem")
