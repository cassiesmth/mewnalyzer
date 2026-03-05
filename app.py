#!/usr/bin/env python3
from analyzer import PEAnalyzer
from colorama import Fore
import argparse
import os
import sys


def appp():
    parser = argparse.ArgumentParser(description='pe file analyzer')
    parser.add_argument('file', help='Path to the PE file for analysis')
    parser.add_argument('-b', '--basic', action='store_true', help='show only basic information')
    parser.add_argument('-s', '--sections', action='store_true', help='show section information')
    parser.add_argument('-i', '--imports', action='store_true', help='show import information')
    parser.add_argument('-e', '--exports', action='store_true', help='show export information')
    parser.add_argument('-p', '--packers', action='store_true', help='detect packers')
    parser.add_argument('-hash', '--hashes', action='store_true', help='calculate hashes')
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{Fore.RED} file not found (╥﹏╥): {Fore.WHITE}{args.file}")
        sys.exit(1)
    
    analyzer = PEAnalyzer(args.file)
    
    # if options not specified, analyze everything
    if not any([args.basic, args.sections, args.imports, args.exports, args.packers, args.hashes]):
        analyzer.analyze_all()
    else:
        if not analyzer.file_load():
            sys.exit(1)  
        if args.basic:
            analyzer.basic_info()
        if args.sections:
            analyzer.sections()
            analyzer.entropy_analysis()
        if args.packers:
            analyzer.detect_packers()
        if args.imports:
            analyzer.print_imports()
        if args.exports:
            analyzer.exports()
        if args.hashes:
            analyzer.calculate_hash()


    
    