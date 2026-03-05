from colorama import init, Fore, Style
import pefile
import math
import argparse
import os
import sys
from collections import Counter
import hashlib
from coloring import coloring

class PEAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.file_size = os.path.getsize(file_path)
        
    def file_load(self):
        # getting your file
        try:
            self.pe = pefile.PE(self.file_path)
            return True
        except Exception as e:
            print(f"{Fore.RED} error downloading  ₍^ >~< ^₎⟆: {e}")
            return False
    
    def shannon(self, data):
        # shannon entropy for data blocks by calculating probability
        if not data:
            return 0
        res = 0
        counter = Counter(data)
        size = len(data)
        for n in counter.values():
            prob = n / size
            res -= prob * math.log2(prob)
        return res
    
    def basic_info(self):
        # PE file information
        print(f"\n{Fore.CYAN} --------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ basic info *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚------- ")
        print(f"ᓚ₍⑅^..^₎ {Fore.MAGENTA}file used: {Fore.WHITE}{self.file_path}")
        print(f"ᓚ₍⑅^..^₎ {Fore.MAGENTA}size: {Fore.WHITE} {self.file_size} bytes\n")
        
        # DOS header
        print(f"{Fore.YELLOW} -------༻*ੈ✩‧₊˚ dos header: ༻*ੈ✩‧₊˚------- ")
        print(f"{Fore.MAGENTA}  > e_magic: {Fore.WHITE}{hex(self.pe.DOS_HEADER.e_magic)}")
        print(f"{Fore.MAGENTA}  > e_lfanew: {Fore.WHITE}{hex(self.pe.DOS_HEADER.e_lfanew)}")
        
        # file header
        print(f"\n{Fore.YELLOW} -------༻*ੈ✩‧₊˚ file header: ༻*ੈ✩‧₊˚------- ")
        print(f"{Fore.MAGENTA}  > machine: {Fore.WHITE}{hex(self.pe.FILE_HEADER.Machine)}")
        print(f"{Fore.MAGENTA}  > sections number: {Fore.WHITE}{self.pe.FILE_HEADER.NumberOfSections}")
        print(f"{Fore.MAGENTA}  > time date stamp: {Fore.WHITE}{self.pe.FILE_HEADER.TimeDateStamp}")
        print(f"{Fore.MAGENTA}  > characteristics: {Fore.WHITE}{hex(self.pe.FILE_HEADER.Characteristics)}")
        
        # optional header
        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            print(f"\n{Fore.YELLOW} -------༻*ੈ✩‧₊˚ optional header: ༻*ੈ✩‧₊˚------- ")
            print(f"{Fore.MAGENTA}  > magic: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.Magic)}")
            print(f"{Fore.MAGENTA}  > entry point addr: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            print(f"{Fore.MAGENTA}  > imagebase: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.ImageBase)}")
            print(f"{Fore.MAGENTA}  > section alignment: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.SectionAlignment)}")
            print(f"{Fore.MAGENTA}  > file alignment: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.FileAlignment)}")
            print(f"{Fore.MAGENTA}  > size of image: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.SizeOfImage)}")
            print(f"{Fore.MAGENTA}  > size of headers: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.SizeOfHeaders)}")
            print(f"{Fore.MAGENTA}  > subsystem: {Fore.WHITE}{hex(self.pe.OPTIONAL_HEADER.Subsystem)}")
    
    def sections(self):
        # sections information
        print(f"\n{Fore.CYAN} -------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ sections information *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚------- ")
        if not hasattr(self.pe, 'sections'):
            print("no sections information :(((")
            return
        print(f"{'₍^. .^₎⟆':<10} {'₍^. .^₎⟆':<12} {'₍^. .^₎⟆':<15} {'₍^. .^₎⟆':<10} {'₍^. .^₎⟆':<12} {'₍^. .^₎⟆':<10} {'₍^. .^₎⟆':<15}")
        print(f"{Fore.MAGENTA}{'name':<10} {'virt size':<12} {'virt addr':<15} {'raw size':<10} {'raw offset':<12} {'entropy':<10} {'characteristics':<15}")
        print("-" * 90)
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            vs = section.Misc_VirtualSize
            va = hex(section.VirtualAddress)
            rs = section.SizeOfRawData
            ro = hex(section.PointerToRawData)
            sd = section.get_data() # section data for entropy calculation
            e = self.shannon(sd) # entropy
            c = hex(section.Characteristics) # characteristics
            print(f"{name:<10} {vs:<12} {va:<15} {rs:<10} {ro:<12} {Fore.RED if e > 7 else Fore.GREEN}{e:<10.4f} {Fore.WHITE}{c:<15}")
    
    def imports(self):
        # imports information
        print(f"\n{Fore.CYAN} -------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ imports *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚------- ")
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("no import information found (╥﹏╥)")
            return
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            print(f"{Fore.YELLOW}DLL: {entry.dll.decode('utf-8', errors='ignore')}")
            for imp in entry.imports:
                if imp.name:
                    print(f"  {hex(imp.address)} - {imp.name.decode('utf-8', errors='ignore')}")
                else:
                    print(f"  {hex(imp.address)} - [Ordinal: {imp.ordinal}]")
    
    def exports(self):
        # exports information
        print(f"\n{Fore.CYAN} -------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ exports *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚------- ")
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("no export information found (╥﹏╥)")
            return
        exports = self.pe.DIRECTORY_ENTRY_EXPORT
        print(f"name: {exports.name.decode('utf-8', errors='ignore')}")
        print(f"base: {exports.base}")
        print(f"functions number: {exports.struct.NumberOfFunctions}")
        print(f"names number: {exports.struct.NumberOfNames}")
        
        print(f"\n{Fore.YELLOW}exported functions:")
        for exp in exports.symbols:
            if exp.name:
                print(f"  {hex(exp.address)} - {exp.name.decode('utf-8', errors='ignore')} (ordinal: {exp.ordinal})")
            else:
                print(f"  {hex(exp.address)} - [Ordinal: {exp.ordinal}]")
    
    def detect_packers(self):
        print(f"\n{Fore.CYAN} -------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ packers detecting *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚------- ")
        # signatures for common packers based on section names, entry point patterns and high entropy sections
        packer_signatures = {
            'UPX': {
                'sections': ['UPX0', 'UPX1'],
                'entry_patterns': [b'UPX!', b'UPX0'],
                'characteristics': 0xE0000000
            },
            'MPRESS': {
                'sections': ['MPRESS1', 'MPRESS2'],
                'entry_patterns': [b'M Press', b'MPr'],
            },
            'ASPack': {
                'sections': ['aspack', 'adata'],
                'entry_patterns': [b'ASPack'],
            },
            'Themida': {
                'sections': ['.themida', 'Themida'],
                'high_entropy_threshold': 7.5,
            },
            'VMProtect': {
                'sections': ['.vmp0', '.vmp1'],
                'entry_patterns': [b'VMP'],
            },
            'Enigma': {
                'sections': ['.enigma'],
            },
            'PECompact': {
                'sections': ['PEC2'],
            },
        }     
        sections = [s.Name.decode('utf-8', errors='ignore').strip('\x00') for s in self.pe.sections]
        detected = []
        for packer_name, signatures in packer_signatures.items():
            # section check
            if 'sections' in signatures:
                if any(section_name in signatures['sections'] for section_name in sections):
                    detected.append(packer_name)
                    continue
            # pattern check
            if 'entry_patterns' in signatures and hasattr(self.pe, 'OPTIONAL_HEADER'):
                try:
                    entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    # getting 256 bytes from entry point for pattern matching
                    entry_data = self.pe.get_data(entry_rva, 256)
                    for pattern in signatures['entry_patterns']:
                        if pattern in entry_data:
                            detected.append(packer_name)
                            break
                except:
                    pass
            # high entropy check
            if 'high_entropy_threshold' in signatures:
                for section in self.pe.sections:
                    entropy = self.shannon(section.get_data())
                    if entropy > signatures['high_entropy_threshold']:
                        detected.append(f"{packer_name} (possibly)")
                        break
        if detected:
            print(f"{Fore.RED}known packers detected (≖_≖ ):")
            for packer in set(detected):
                print(f"  - {packer}")
        else:
            print(f"{Fore.GREEN}known packers not detected (╥﹏╥)")
    
    def calculate_hash(self):
        print(f"\n{Fore.CYAN}-------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ hash calculatng *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚-------")
        with open(self.file_path, 'rb') as f:
            data = f.read()
            print(f"MD5:    {hashlib.md5(data).hexdigest()}")
            print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
            print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

    def entropy_analysis(self):
        print(f"\n{Fore.CYAN}-------*ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚ entropy analysis *ੈ✩‧₊˚༺☆༻*ੈ✩‧₊˚-------")
        high_entropy = []
        for s in self.pe.sections:
            data = s.get_data()
            entropy = self.shannon(data)
            # if high entropy
            if entropy > 7.0:
                name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
                high_entropy.append((name, entropy))
        if high_entropy:
            print(f"{Fore.RED}high entropy sections found (≖_≖ ):")
            for name, entropy in high_entropy:
                print(f"  {name}: {entropy:.4f} (possible encryption or packing)")
        else:
            print(f"{Fore.GREEN}high entropy sections not found ◝(ᵔᗜᵔ)◜")
    
    def analyze_all(self):
        if not self.file_load():
            return
        self.basic_info()
        self.sections()
        self.entropy_analysis()
        self.detect_packers()
        self.imports()
        self.exports()
        self.calculate_hash()