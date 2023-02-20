from pwd import getpwuid
import sys
import os
import json
import lief
import lib.pattern as pattern
import lib.readelf as readelf
import lib.pe_printer as printer

SUMMARY_TAG = "<SUMMARY>"
SUMMARY_ENDTAG = "<SUMMARY_END>"

BINARY_TAG = "<BINARY_ANALYSIS>"
BINARY_ENDTAG = "<BINARY_ANALYSIS_END>"

# KEYS: Ownership / S-bit / Capabilities / Sections / Packers
summary_lin = {"Ownership": pattern.SAFE,
               "S-bit": pattern.SAFE,
               "Capabilities": pattern.SAFE,
               "Sections": pattern.SAFE,
               "Packers": pattern.SAFE}

# KEYS: Ownership / S-bit / Capabilities / Sections / Packers
summary_win = {"Packers": pattern.SAFE}


def check_packers(binary):
    """ Check if the PE Executable is Packed """
    suspect_sections = []
    safe = True

    for section_name in binary.sections:
        if section_name.name in pattern.packers_sections.keys():
            safe = False
            suspect_sections.append(section_name.name)
    if not safe:
        summary_win['Packers'] = pattern.NOT_SAFE + \
            " | " + str(suspect_sections)


def check_sbit(file):
    """ Check if the s-bit is setted on the ELF File """

    sbit = oct(os.stat(file).st_mode)[-4:][0]
    if int(sbit) >= 4:
        summary_lin['S-bit'] = pattern.NOT_SAFE


def check_section(info):
    """ Check if the ELF has no Sections """

    if pattern.NO_SECTION in info:
        summary_lin["Sections"] = pattern.NOT_SAFE


def check_capabilities(file):
    """ Check if the ELF has some Capabilities """

    caps = os.popen(f"getcap {file}").read()
    if caps != "":
        summary_lin["Capabilities"] = pattern.NOT_SAFE + " = " + caps[:-1]


def check_ownership(file):
    """ Check if the file has root as owner """

    owner = getpwuid(os.stat(file).st_uid).pw_name
    if owner == "root":
        summary_lin["Ownership"] = pattern.NOT_SAFE


def elf_analysis(file, report):
    """ Launch all tests on the ELF file """
    elf = open(file, 'rb')
    elf_reader = readelf.ReadElf(elf, report)

    elf_reader.display_file_header()
    elf_reader.display_section_headers()
    elf_reader.display_program_headers()
    elf.close()


def pe_analysis(binary, report):
    """ Analyze te PE Binary """
    analysis_report = printer.pe_reader(binary)
    report.write(analysis_report)


def analyze(file_path, report_path):
    """ Analyze the binary, distinguishing PE from ELF """
    report_file = open(report_path, 'w')
    file_info = os.popen(f"file {file_path}").read()

    if pattern.ELF_FORMAT in file_info:
        # Verifica se il malware cambia i suoi permessi a runtime
        os.system(f"chmod 777 /{file_path} ; ./{file_path}")
        check_ownership(file_path)
        check_capabilities(file_path)
        check_section(file_info)
        check_sbit(file_path)

        # Write Summary on Report
        sum = str(json.dumps(summary_lin, indent=2))
        summary_str = SUMMARY_TAG + "\n" + sum + "\n" + \
            SUMMARY_ENDTAG + "\n\n" + BINARY_TAG + "\n"
        report_file.write(summary_str)

        # Start ELF Analysis
        elf_analysis(file_path, report_file)
        report_file.write("\n"+BINARY_ENDTAG+"\n")

    elif pattern.EXE_FORMAT in file_info:
        pe_binary = lief.parse(file_path)
        check_packers(pe_binary)
        # Write Summary on Report
        sum = str(json.dumps(summary_win, indent=2))
        summary_str = SUMMARY_TAG + "\n" + sum + "\n" + \
            SUMMARY_ENDTAG + "\n\n" + BINARY_TAG + "\n"
        report_file.write(summary_str)
        pe_analysis(pe_binary, report_file)
        report_file.write("\n"+BINARY_ENDTAG+"\n")

    else:
        sum = str(json.dumps(summary_lin, indent=2))
        summary_str = SUMMARY_TAG + "\n" + sum + "\n" + \
            SUMMARY_ENDTAG + "\n\n" + BINARY_TAG + "\n"
        report_file.write(summary_str)
        report_file.write(file_info)
        report_file.write("\n"+BINARY_ENDTAG+"\n")

    report_file.close()


if __name__ == "__main__":
    analyze(sys.argv[1], sys.argv[2])
