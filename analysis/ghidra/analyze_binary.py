#!/usr/bin/env python3
"""
Ghidra Automated Binary Analysis Script for MASARE
Purpose: Headless Ghidra analysis with automated IOC extraction
Author: Security Research Team
Last Updated: 2025-11-15

Run via Ghidra headless mode:
    analyzeHeadless /tmp/ghidra_projects MalwareProject -import /path/to/malware.exe \
        -scriptPath /home/user/MASARE/analysis/ghidra \
        -postScript analyze_binary.py /path/to/output.json
"""

import json
import sys
from collections import defaultdict

# Ghidra imports (available when running in Ghidra environment)
try:
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SymbolType
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
except ImportError:
    print("[!] This script must be run within Ghidra environment")
    print("[i] Use: analyzeHeadless <project_path> <project_name> -import <binary> -postScript analyze_binary.py")
    sys.exit(1)


class GhidraMalwareAnalyzer:
    """Automated malware analysis using Ghidra"""

    def __init__(self, program, output_path):
        self.program = program
        self.output_path = output_path
        self.results = {
            'metadata': {},
            'functions': [],
            'strings': [],
            'imports': [],
            'exports': [],
            'suspicious_patterns': [],
            'api_calls': defaultdict(int),
            'code_references': [],
        }

    def analyze(self):
        """Execute full analysis pipeline"""
        print("[*] Starting Ghidra automated analysis...")

        self.extract_metadata()
        self.analyze_functions()
        self.extract_strings()
        self.extract_imports_exports()
        self.detect_suspicious_patterns()
        self.generate_iocs()

        # Save results
        self.save_results()

        print("[✓] Analysis complete")

    def extract_metadata(self):
        """Extract binary metadata"""
        print("[*] Extracting metadata...")

        mem = self.program.getMemory()
        listing = self.program.getListing()

        self.results['metadata'] = {
            'name': self.program.getName(),
            'language': str(self.program.getLanguage()),
            'compiler': str(self.program.getCompilerSpec()),
            'format': self.program.getExecutableFormat(),
            'entry_point': str(self.program.getMinAddress()),
            'image_base': str(self.program.getImageBase()),
            'size': mem.getSize(),
            'num_functions': self.program.getFunctionManager().getFunctionCount(),
            'num_segments': len(list(mem.getBlocks())),
        }

    def analyze_functions(self):
        """Analyze all functions in the binary"""
        print("[*] Analyzing functions...")

        fm = self.program.getFunctionManager()
        functions = []

        for func in fm.getFunctions(True):
            func_data = {
                'name': func.getName(),
                'entry_point': str(func.getEntryPoint()),
                'size': func.getBody().getNumAddresses(),
                'is_thunk': func.isThunk(),
                'is_external': func.isExternal(),
                'calling_convention': str(func.getCallingConventionName()),
                'num_params': func.getParameterCount(),
                'num_local_vars': len(func.getAllVariables()),
                'complexity': self.calculate_cyclomatic_complexity(func),
            }

            # Categorize by risk level
            func_data['risk_level'] = self.assess_function_risk(func)

            # Extract called functions
            func_data['calls'] = self.get_called_functions(func)

            functions.append(func_data)

        self.results['functions'] = functions
        print(f"[+] Analyzed {len(functions)} functions")

    def calculate_cyclomatic_complexity(self, func):
        """Calculate cyclomatic complexity (basic blocks)"""
        try:
            bbm = BasicBlockModel(self.program)
            blocks = bbm.getCodeBlocksContaining(func.getBody(), monitor)
            return len(list(blocks))
        except:
            return 0

    def assess_function_risk(self, func):
        """Assess function risk level based on suspicious patterns"""
        func_name = func.getName().lower()

        # Critical risk indicators
        critical_apis = [
            'winexec', 'shellexecute', 'createprocess', 'virtualallocex',
            'writeprocessmemory', 'createremotethread', 'loadlibrary',
            'getprocaddress', 'urldownloadtofile', 'internetopen'
        ]

        # High risk indicators
        high_risk_apis = [
            'writefile', 'readfile', 'regsetvalue', 'regdeletekey',
            'cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt'
        ]

        if any(api in func_name for api in critical_apis):
            return 'CRITICAL'
        elif any(api in func_name for api in high_risk_apis):
            return 'HIGH'
        elif func.isExternal():
            return 'LOW'
        else:
            return 'MEDIUM'

    def get_called_functions(self, func):
        """Extract functions called by this function"""
        called = []
        for ref in func.getCalledFunctions(monitor):
            called.append(ref.getName())
        return called

    def extract_strings(self):
        """Extract ASCII and Unicode strings"""
        print("[*] Extracting strings...")

        strings = []
        mem = self.program.getMemory()
        listing = self.program.getListing()

        # Get all defined strings in the binary
        data_iterator = listing.getDefinedData(True)
        for data in data_iterator:
            if data.hasStringValue():
                string_value = data.getValue()
                if string_value:
                    strings.append({
                        'address': str(data.getAddress()),
                        'value': str(string_value),
                        'length': len(str(string_value)),
                        'type': str(data.getDataType()),
                        'xrefs': len(list(data.getReferenceIteratorTo())),
                    })

        # Filter suspicious strings
        self.results['strings'] = strings
        self.results['suspicious_strings'] = self.filter_suspicious_strings(strings)

        print(f"[+] Extracted {len(strings)} strings ({len(self.results['suspicious_strings'])} suspicious)")

    def filter_suspicious_strings(self, strings):
        """Filter strings for suspicious patterns"""
        suspicious = []

        suspicious_patterns = [
            # C2 indicators
            'http://', 'https://', 'ftp://',
            # File paths
            'appdata', 'temp', 'program files',
            # Registry
            'software\\', 'currentversion\\run',
            # Crypto
            'password', 'key', 'encrypt', 'decrypt',
            # Network
            'socket', 'connect', 'bind', 'listen',
            # Process
            'kernel32', 'ntdll', 'advapi32',
        ]

        for string_obj in strings:
            value = string_obj['value'].lower()
            for pattern in suspicious_patterns:
                if pattern in value:
                    suspicious.append(string_obj)
                    break

        return suspicious

    def extract_imports_exports(self):
        """Extract imported and exported functions"""
        print("[*] Extracting imports and exports...")

        # Extract imports
        imports = []
        symbol_table = self.program.getSymbolTable()
        for symbol in symbol_table.getExternalSymbols():
            imports.append({
                'name': symbol.getName(),
                'address': str(symbol.getAddress()),
                'library': str(symbol.getParentNamespace()),
            })

        self.results['imports'] = imports

        # Extract exports
        exports = []
        for symbol in symbol_table.getSymbolIterator():
            if symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isExternalEntryPoint():
                exports.append({
                    'name': symbol.getName(),
                    'address': str(symbol.getAddress()),
                })

        self.results['exports'] = exports

        print(f"[+] Found {len(imports)} imports, {len(exports)} exports")

    def detect_suspicious_patterns(self):
        """Detect common malware patterns"""
        print("[*] Detecting suspicious patterns...")

        patterns = []

        # 1. Suspicious API combinations
        api_combos = self.detect_api_combinations()
        patterns.extend(api_combos)

        # 2. Anti-analysis techniques
        anti_analysis = self.detect_anti_analysis()
        patterns.extend(anti_analysis)

        # 3. Packer/obfuscation detection
        obfuscation = self.detect_obfuscation()
        patterns.extend(obfuscation)

        self.results['suspicious_patterns'] = patterns
        print(f"[+] Detected {len(patterns)} suspicious patterns")

    def detect_api_combinations(self):
        """Detect suspicious API call combinations"""
        patterns = []

        imported_apis = set(imp['name'].lower() for imp in self.results['imports'])

        # Code injection pattern
        injection_apis = ['virtualallocex', 'writeprocessmemory', 'createremotethread']
        if all(api in imported_apis for api in injection_apis):
            patterns.append({
                'type': 'Code Injection',
                'severity': 'CRITICAL',
                'description': 'Process injection APIs detected',
                'indicators': injection_apis,
            })

        # Keylogging pattern
        keylog_apis = ['setwindowshookex', 'getkeystate', 'getasynckeystate']
        if any(api in imported_apis for api in keylog_apis):
            patterns.append({
                'type': 'Keylogging',
                'severity': 'HIGH',
                'description': 'Keyboard monitoring APIs detected',
                'indicators': [api for api in keylog_apis if api in imported_apis],
            })

        # Persistence pattern
        persistence_apis = ['regsetvalue', 'regcreatekey']
        if any(api in imported_apis for api in persistence_apis):
            patterns.append({
                'type': 'Registry Persistence',
                'severity': 'MEDIUM',
                'description': 'Registry modification APIs detected',
                'indicators': [api for api in persistence_apis if api in imported_apis],
            })

        return patterns

    def detect_anti_analysis(self):
        """Detect anti-analysis techniques"""
        patterns = []

        imported_apis = set(imp['name'].lower() for imp in self.results['imports'])

        # Debugger detection
        debug_apis = ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess']
        if any(api in imported_apis for api in debug_apis):
            patterns.append({
                'type': 'Anti-Debugging',
                'severity': 'HIGH',
                'description': 'Debugger detection APIs found',
                'indicators': [api for api in debug_apis if api in imported_apis],
            })

        # VM detection
        vm_strings = [s['value'].lower() for s in self.results['strings']]
        vm_indicators = ['vmware', 'virtualbox', 'vbox', 'qemu', 'xen']
        if any(indicator in ' '.join(vm_strings) for indicator in vm_indicators):
            patterns.append({
                'type': 'VM Detection',
                'severity': 'MEDIUM',
                'description': 'VM detection strings found',
                'indicators': [i for i in vm_indicators if i in ' '.join(vm_strings)],
            })

        return patterns

    def detect_obfuscation(self):
        """Detect packing/obfuscation"""
        patterns = []

        # High entropy sections (indicator of packing)
        # Simplified check: very few imports = likely packed
        if len(self.results['imports']) < 10:
            patterns.append({
                'type': 'Potential Packing',
                'severity': 'MEDIUM',
                'description': 'Very few imports detected, binary may be packed',
                'indicators': [f"Only {len(self.results['imports'])} imports"],
            })

        # No recognizable strings (obfuscation)
        if len(self.results['strings']) < 20:
            patterns.append({
                'type': 'String Obfuscation',
                'severity': 'LOW',
                'description': 'Very few strings detected, may be obfuscated',
                'indicators': [f"Only {len(self.results['strings'])} strings"],
            })

        return patterns

    def generate_iocs(self):
        """Generate IOCs from static analysis"""
        print("[*] Generating IOCs...")

        iocs = {
            'suspicious_apis': [],
            'suspicious_strings': [],
            'network_indicators': [],
        }

        # Suspicious APIs
        for func in self.results['functions']:
            if func['risk_level'] in ['CRITICAL', 'HIGH']:
                iocs['suspicious_apis'].append({
                    'api': func['name'],
                    'risk': func['risk_level'],
                })

        # Network indicators from strings
        for string_obj in self.results['strings']:
            value = string_obj['value']
            if any(proto in value.lower() for proto in ['http://', 'https://', 'ftp://']):
                iocs['network_indicators'].append(value)

        self.results['iocs'] = iocs

    def save_results(self):
        """Save analysis results to JSON"""
        print(f"[*] Saving results to {self.output_path}...")

        with open(self.output_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"[✓] Results saved to {self.output_path}")


# Main execution (when run in Ghidra)
if __name__ == '__main__':
    # Get output path from command line
    output_path = '/tmp/ghidra_analysis.json'
    if len(sys.argv) > 1:
        output_path = sys.argv[1]

    # Get current program from Ghidra context
    current_program = currentProgram
    monitor = ConsoleTaskMonitor()

    # Run analysis
    analyzer = GhidraMalwareAnalyzer(current_program, output_path)
    analyzer.analyze()

    print("[✓] Ghidra analysis complete")
