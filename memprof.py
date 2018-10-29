#Author: Vijay Nag
#!/usr/bin/python

import re, os, sys, time
from collections import OrderedDict

class Proc(object):

  def __init__(self,pid=None):
    self.pid = pid
    self.smaps={}
    try:
      p=file("/proc/self/smaps").read().splitlines(True)
    except:
      print "Procfs not mounted ?"
      sys.exit(-1)
    self.name=file("/proc/"+pid+"/cmdline").read()[:-1]
    if self.name.rfind('/') > -1:
      idx=self.name.rfind('/')
      self.name=self.name[idx+1:idx+15].replace('\0', ' ')
    else:
      self.name=self.name[:25].replace('\0', ' ')
    self.smaps=self.parse_smaps()

  def read_smaps(self):
    return file("/proc/"+self.pid+"/smaps").read().splitlines(True)

  def parse_smaps(self, pid=None):
    start=None
    end = None
    pssSize = None
    rssSize = None
    smaps={}
    for line in self.read_smaps():
      l = line.split() #['00400000-006bd000', 'r-xp', '00000000', 'fc:00', '659366', '/usr/bin/python2.7']
      if '-' in l[0]: #new segment
        start,end=l[0].split('-')
        smaps[start] = dict(start=int(start,16),end=int(end,16))
      elif 'kB' in l: #['Rss:', '1448', 'kB']
        smaps[start][l[0][:-1]]=int(l[1],10)
    return smaps

  def proc_stat(self):
    t=dict(Rss=0,Pss=0,Private_Dirty=0,Private_Clean=0,Swap=0,start=0,end=0)
    for s in self.smaps.iterkeys():
      for k in t:
        t[k] += self.smaps[s].get(k,0)
    t["PID"] = self.pid
    t["Name"] = self.name
    t["Uss"] = t["Private_Dirty"] + t["Private_Clean"]
    t["Vss"] = (t["end"]-t["start"])/1024
    return t

  def dump_stats(self):
    print "Process "+self.pid+" Summary:"
    for s in self.smaps.iterkeys():
      print self.smaps[s]

  def get_stat(self): #list of stats needed
    t=self.proc_stat()
    for k in t:
      print "%s:%s"%(k,str(t[k]))

class ProcFs(object):

  def __init__(self):
    self.pids = []
    self.memTotal=0
    self.mem={}
    self.dash='-'*110

  def isuserproc(self,pid):
    try:
      pid=file("/proc/"+pid+"/cmdline").read()
      if '' == pid:
        return False
      return True
    except:
      return False

  def update_proc_list(self):
    self.pids = [ e for e in os.listdir('/proc')
                  if e.isdigit() and self.isuserproc(e)]

  def print_dict(self, d, no_header=False, no_val=False, indent=13):
    l=len(d.keys())
    fmt='{%s:<%d}'*l
    tup=tuple(d.keys())
    ind=l*(indent,)
    s=fmt%(tuple([v for u in zip(tup,ind) for v in u]))
    if not no_header:
      print s.format(**dict(zip(d.keys(),d.keys())))
    if not no_val:
      print s.format(**d)

  def dump_proc_mem_stat(self):
    f=[ v.split() for v in file("/proc/meminfo").read().splitlines(True)]
    d=dict(zip(map(lambda x: x[0][:-1], f), map(lambda x: int(x[1]), f)))
    self.memTotal=d["MemTotal"]
    d["SwapUsed"]=d["SwapTotal"]-d["SwapFree"]
    print self.dash
    mtot=dict(MemTotal=d["MemTotal"], MemFree=d["MemFree"], Buffers=d["Buffers"],
           Cached=d["Cached"], SwapUsed=d["SwapUsed"],SwapCached=d["SwapCached"])
    self.print_dict(mtot)
    print self.dash

  def dump_cgroup_mem_stat(self):
    f=[ v.split() for v in file("/sys/fs/cgroup/memory/memory.stat").read().splitlines(True)]
    d=dict(zip(map(lambda x: x[0], f), map(lambda x: int(x[1]), f)))
    d["CGRss"]=d["rss"]
    d["CGCache"]=d["cache"]
    d["MemTotal"]=self.memTotal
    d["RssTotal"]=d["rss"]+d["cache"]+d["mapped_file"]
    d["Mapped_file"]=d["mapped_file"]
    d["CGMemUsage"] = file("/sys/fs/cgroup/memory/memory.usage_in_bytes").read().splitlines(True)[0].strip()
    print "Cgroup Stats Summary"
    print self.dash
    cmtot = dict(MemTotal=round(float(d["MemTotal"]/1024.0/1024.0),2),
                 CGRss=round(float(d["CGRss"]/1024.0/1024.0),2),
                 RssTotal=round(float(d["RssTotal"]/1024.0/1024.0),2),
                 CGMemUsage=round(float(int(d["CGMemUsage"])/1024.0/1024.0),2),
                 CGCache=round(float(d["cache"])/1024.0/1024.0),
                 Mapped_file=round(float(d["Mapped_file"])/1024.0/1024.0))
    self.print_dict(cmtot)
    print self.dash

  def dump_stats(self):
    self.dump_proc_mem_stat()
    for pid in self.pids:
      t=Proc(pid)
      self.mem[pid] = t.proc_stat()
    indent=17

    tup=("Name","PID","Uss","Pss","Rss","Vss","Swap")
    d=OrderedDict(zip(tup, tup))
    self.print_dict(d,no_val=True, indent=indent)
    print self.dash
    for pid in self.pids:
      d=OrderedDict([(v,self.mem[pid][v]) for v in tup])
      self.print_dict(d, no_header=True, indent=indent)
    print self.dash
    summary = dict(Name="",
                   PID=len(self.mem),
                   Uss=sum(map(lambda x: x["Uss"], map(lambda x: p.mem[x], p.mem))),
                   Pss=sum(map(lambda x: x["Pss"], map(lambda x: p.mem[x], p.mem))),
                   Rss=sum(map(lambda x: x["Rss"], map(lambda x: p.mem[x], p.mem))),
                   Vss=sum(map(lambda x: x["Vss"], map(lambda x: p.mem[x], p.mem))),
                   Swap=sum(map(lambda x: x["Swap"], map(lambda x: p.mem[x], p.mem))))
    d=OrderedDict([(v,summary[v]) for v in tup])
    self.print_dict(d,no_header=True,indent=indent)
    print self.dash
    self.dump_cgroup_mem_stat()

if __name__ == "__main__":
  try:
    while True:
      os.system("clear_console")
      p=ProcFs()
      p.update_proc_list()
      p.dump_stats()
      time.sleep(1)
  except KeyboardInterrupt:
    sys.exit(0)
