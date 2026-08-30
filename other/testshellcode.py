import qiling
from capstone import *
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
import sys

#code = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
text = bytes.fromhex('4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05')
ql = Qiling(code=text, archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DEBUG)
ql.run()
print(ql.mem.read(0x11feff8, 16))

#for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, 0x1000):
#    print(f'{i.address:x}  {i.mnemonic} {i.op_str}')
