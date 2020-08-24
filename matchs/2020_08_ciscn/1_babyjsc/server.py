import sys
import tempfile
import os

size = int(input())
assert(size < 1024*1024) #1MB max
script = sys.stdin.read(size) # reads one byte at a time, similar to getchar()

temp = tempfile.mktemp()
with open(temp, "w") as f:
	f.write(script)
print ('aaa')
# os.environ['LD_PRELOAD'] = "./libJavaScriptCore.so.1"
cmd = "LD_PRELOAD=/home/ctf/libJavaScriptCore.so.1 /home/ctf/jsc " + temp
os.system(cmd)
