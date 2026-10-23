import ast
import types
import unittest
from pathlib import Path


class ContextMemoryTests(unittest.TestCase):
    def test_restore_preserves_memory_bytes(self):
        source = Path(__file__).with_name("uEmu.py")
        tree = ast.parse(source.read_text(encoding="utf-8"))
        engine = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == "uEmuUnicornEngine")
        method = next(node for node in engine.body
                      if isinstance(node, ast.FunctionDef) and node.name == "set_context")
        namespace = {
            "UcError": type("UcError", (Exception,), {}),
            "uemu_log": lambda *args: None,
            "IDAAPI_SetColor": lambda *args: None,
            "CIC_ITEM": 0,
            "UEMU_CONFIG": types.SimpleNamespace(IDAViewColor_PC=0),
        }
        exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"), namespace)

        class MemoryMock:
            def mem_map(self, address, size, permissions):
                self.mapping = (address, size, permissions)

            def mem_write(self, address, data):
                if not isinstance(data, bytes):
                    raise TypeError("memory writes require bytes")
                self.written = (address, data)

            def reg_read(self, register):
                return 0x1000

        for payload in (bytes(range(256)) * 16, bytearray(range(256)) * 16):
            with self.subTest(payload_type=type(payload).__name__):
                memory = MemoryMock()
                instance = types.SimpleNamespace(mu=memory, uc_reg_pc=0, emuActive=True)
                namespace["set_context"](instance, {
                    "cpu": [], "cpu_ext": [], "mem": [[0x1000, 0x1fff, 7, payload]]
                })
                self.assertEqual(memory.mapping, (0x1000, 4096, 7))
                self.assertEqual(memory.written, (0x1000, bytes(payload)))
                self.assertEqual(instance.pc, 0x1000)


if __name__ == "__main__":
    unittest.main()
