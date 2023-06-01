import sys

DEBUG = False

def dbg(line, force=False, end='\n', **kwargs):
    if DEBUG or force:
        print(line, flush=True, file=sys.stderr, end=end, **kwargs)
        pass
    pass

def prnt(line, force=False, **kwargs):
    dbg(line, force=force)
    print(line, flush=True, **kwargs)
    pass

def inp(lines=1, chars=0, force=False):
    line = ''
    for _ in range(lines):
        line = input()
        dbg(line, force=force)
    if chars > 0:
        dbg(sys.stdin.read(chars), force=force, end='')
    return line
