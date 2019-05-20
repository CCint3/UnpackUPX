import sys
import struct
import os

class Elf32_Ehdr:
  fmt_str = "<16sHHIIIIIHHHHHH"
  sizeof = struct.calcsize(fmt_str)

  def __init__(self):
    self.e_ident = ""
    self.e_type = 0
    self.e_machine = 0
    self.e_version = 0
    self.e_entry = 0
    self.e_phoff = 0
    self.e_shoff = 0
    self.e_flags = 0
    self.e_ehsize = 0
    self.e_phentsize = 0
    self.e_phnum = 0
    self.e_shentsize = 0
    self.e_shnum = 0
    self.e_shstrndx = 0

  def setFields(self, data):
    data = struct.unpack(self.fmt_str, data)
    self.e_ident = data[0]
    self.e_type = data[1]
    self.e_machine = data[2]
    self.e_version = data[3]
    self.e_entry = data[4]
    self.e_phoff = data[5]
    self.e_shoff = data[6]
    self.e_flags = data[7]
    self.e_ehsize = data[8]
    self.e_phentsize = data[9]
    self.e_phnum = data[10]
    self.e_shentsize = data[11]
    self.e_shnum = data[12]
    self.e_shstrndx = data[13]

  def getFields(self):
    return struct.pack(self.fmt_str, \
                self.e_ident, \
                self.e_type, \
                self.e_machine, \
                self.e_version, \
                self.e_entry, \
                self.e_phoff, \
                self.e_shoff, \
                self.e_flags, \
                self.e_ehsize, \
                self.e_phentsize, \
                self.e_phnum, \
                self.e_shentsize, \
                self.e_shnum, \
                self.e_shstrndx)

  def fix(self, data = None, offset = 0):
    self.e_shoff = 0
    self.e_shnum = 0
    self.e_shstrndx = 0
    self.e_shentsize = 0
    if data != None:
      self_data = self.getFields()
      return data[0 : offset] + self_data + data[offset + self.sizeof : len(data)]
    return data


class Elf32_Phdr:
  fmt_str = "<IIIIIIII"
  sizeof = struct.calcsize(fmt_str)

  def __init__(self):
    self.p_type = 0
    self.p_offset = 0
    self.p_vaddr = 0
    self.p_paddr = 0
    self.p_filesz = 0
    self.p_memsz = 0
    self.p_flags = 0
    self.p_align = 0

  def setFields(self, data):
    data = struct.unpack(self.fmt_str, data)
    self.p_type = data[0]
    self.p_offset = data[1]
    self.p_vaddr = data[2]
    self.p_paddr = data[3]
    self.p_filesz = data[4]
    self.p_memsz = data[5]
    self.p_flags = data[6]
    self.p_align = data[7]

  def getFields(self):
    return struct.pack(self.fmt_str, \
                self.p_type, \
                self.p_offset, \
                self.p_vaddr, \
                self.p_paddr, \
                self.p_filesz, \
                self.p_memsz, \
                self.p_flags, \
                self.p_align)

  def fix(self, data = None, offset = 0):
    self.p_filesz = self.p_memsz
    self.p_offset = self.p_vaddr
    if data != None:
      self_data = self.getFields()
      return data[0 : offset] + self_data + data[offset + self.sizeof : len(data)]
    return data

class Elf32_Dyn:
  fmt_str = "<II"
  sizeof = struct.calcsize(fmt_str)

  def __init__(self):
    self.d_tag = 0
    self.d_val = 0

  def setFields(self, data):
    data = struct.unpack(self.fmt_str, data)
    self.d_tag = data[0]
    self.d_val = data[1]

  def getFields(self):
    return struct.pack(self.fmt_str, self.d_tag, self.d_val)

  def fix(self, data = None, offset = 0):
    if data != None:
      self_data = self.getFields()
      return data[0 : offset] + self_data + data[offset + self.sizeof : len(data)]
    return data

class Elf32_Rel:
  fmt_str = "<II"
  sizeof = struct.calcsize(fmt_str)

  def __init__(self):
    self.r_offset = 0
    self.r_info = 0

  def setFields(self, data):
    data = struct.unpack(self.fmt_str, data)
    self.r_offset = data[0]
    self.r_info = data[1]

  def getFields(self):
    return struct.pack(self.fmt_str, self.r_offset, self.r_info)

  def fix(self, data = None, offset = 0):
    if data != None:
      self_data = self.getFields()
      return data[0 : offset] + self_data + data[offset + self.sizeof : len(data)]
    return data


def get_ehdr(data, offset = 0):
  ehdr = Elf32_Ehdr()
  ehdr.setFields(data[offset : offset + Elf32_Ehdr.sizeof])
  return ehdr

def get_phdr(data, offset = 0):
  phdr = Elf32_Phdr()
  phdr.setFields(data[offset : offset + Elf32_Phdr.sizeof])
  return phdr

def get_dynamic(data, offset = 0):
  dyn = Elf32_Dyn()
  dyn.setFields(data[offset : offset + Elf32_Dyn.sizeof])
  return dyn

def get_rel(data, offset = 0):
  rel = Elf32_Rel()
  rel.setFields(data[offset : offset + Elf32_Rel.sizeof])
  return rel

def get_phdrs(data, ehdr):
  phdrs = []
  for i in range(ehdr.e_phnum):
    phdrs.append(get_phdr(data, ehdr.e_phoff + i * Elf32_Phdr.sizeof))
  return phdrs

def get_dynamics(data, phdr):
  dynamics = []
  i = 0
  while True:
    dyn = get_dynamic(data, phdr.p_vaddr + i * Elf32_Dyn.sizeof)
    if dyn.d_tag == 0:
      break
    i += 1
    dynamics.append(dyn)
  return dynamics

def get_rels(data, offset, relsz):
  rels = []
  for i in range(relsz / 8):
    rel = get_rel(data, offset + i * Elf32_Rel.sizeof)
    rels.append(rel)
  return rels

def on_dump_end(data):
  ehdr  = get_ehdr(data, 0)
  data = ehdr.fix(data, 0)

  phdrs = get_phdrs(data, ehdr)
  dynamic_phdr = None
  dynamics = None
  rels = None
  global_offset_table = 0
  plt_rel_sz = 0
  jmp_rel = 0
  for i in range(len(phdrs)):
    phdr = phdrs[i]
    data = phdr.fix(data, ehdr.e_phoff + i * phdr.sizeof)
    if phdr.p_type == 2: # PT_DYNAMIC
      dynamic_phdr = phdr
      dynamics = get_dynamics(data, phdr)

  if dynamics == None:
    print "not found PT_DYNAMIC"
    return
  for i in range(len(dynamics)):
    dyn = dynamics[i]
    if dyn.d_tag == 3: # DT_PLTGOT
      global_offset_table = dyn.d_val
    elif dyn.d_tag == 2: # DT_PLTRELSZ
      plt_rel_sz = dyn.d_val
    elif dyn.d_tag == 0x17: # DT_JMPREL
      jmp_rel = dyn.d_val
    elif dyn.d_tag == 0x0C: # DT_INIT
      dyn.d_tag = 0x10
      dyn.d_val = 0
      data = dyn.fix(data, dynamic_phdr.p_vaddr + i * dyn.sizeof)

  if plt_rel_sz != 0 and jmp_rel != 0:
    rels = get_rels(data, jmp_rel, plt_rel_sz)
  if global_offset_table != 0 and rels != None:
    for i in range(len(rels)):
      rels[i].r_offset = global_offset_table + 0xC + i * 4
      data = rels[i].fix(data, jmp_rel + i * Elf32_Rel.sizeof)
  with open("./fixed_dump.so", "w+b") as fd:
    fd.write(data)


def main():
  if len(sys.argv) < 2:
    print "please input dump file name."
    return
  filepath = sys.argv[1]
  #filepath = "E:\\Vehicle\\AutelLib_20190509\\libMaxiDas.sodump"
  filedata = ""
  with open(filepath, "rb") as fd:
    for line in fd:
      filedata += line
  on_dump_end(filedata)



if __name__ == "__main__":
    main()