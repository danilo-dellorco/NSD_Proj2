import lief
from lief import PE
import sys
import io


def pe_reader(binary):

    rep_str = ""

    rep_str += print_information(binary)
    rep_str += print_header(binary)
    rep_str += print_data_directories(binary)
    rep_str += print_sections(binary)
    rep_str += print_symbols(binary)
    rep_str += print_imports(binary)
    rep_str += print_tls(binary)
    # rep_str += print_relocations(binary)
    rep_str += print_export(binary)
    rep_str += print_debug(binary)
    rep_str += print_signature(binary)
    rep_str += print_rich_header(binary)
    rep_str += print_load_configuration(binary)
    rep_str += print_ctor(binary)
    rep_str += print_exception_functions(binary)
    rep_str += print_functions(binary)
    rep_str += print_delay_imports(binary)

    return rep_str


def print_information(binary):
    information = "== Information ==\n"
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    information += format_str.format("Name:",         binary.name) + "\n" \
        + (format_hex.format("Virtual size:", binary.virtual_size)) + "\n" \
        + (format_str.format("Imphash:",      PE.get_imphash(binary))) + "\n" \
        + (format_str.format("PIE:",          str(binary.is_pie))) + "\n" \
        + (format_str.format("NX:",           str(binary.has_nx))) + "\n"

    return information


def print_header(binary):
    header_str = "\n== Dos Header ==\n"
    dos_header = binary.dos_header
    header = binary.header
    optional_header = binary.optional_header

    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    header_str += (format_str.format("Magic:",
                                     str((dos_header.magic)))) + "\n" \
        + (format_dec.format("Used bytes in the last page:",
                             dos_header.used_bytes_in_the_last_page)) + "\n"  \
        + (format_dec.format("File size in pages:",
                             dos_header.file_size_in_pages)) + "\n"  \
        + (format_dec.format("Number of relocations:",
                             dos_header.numberof_relocation)) + "\n"  \
        + (format_dec.format("Header size in paragraphs:",
                             dos_header.header_size_in_paragraphs)) + "\n"  \
        + (format_dec.format("Minimum extra paragraphs:",
                             dos_header.minimum_extra_paragraphs)) + "\n"  \
        + (format_dec.format("Maximum extra paragraphs",
                             dos_header.maximum_extra_paragraphs)) + "\n"  \
        + (format_dec.format("Initial relative SS",
                             dos_header.initial_relative_ss)) + "\n"  \
        + (format_hex.format("Initial SP:",                  dos_header.initial_sp)) + "\n"  \
        + (format_hex.format("Checksum:",                    dos_header.checksum)) + "\n"  \
        + (format_dec.format("Initial IP:",                  dos_header.initial_ip)) + "\n"  \
        + (format_dec.format("Initial CS:",
                             dos_header.initial_relative_cs)) + "\n"  \
        + (format_hex.format("Address of relocation table:",
                             dos_header.addressof_relocation_table)) + "\n"  \
        + (format_dec.format("Overlay number:",
                             dos_header.overlay_number)) + "\n"  \
        + (format_dec.format("OEM ID:",                      dos_header.oem_id)) + "\n"  \
        + (format_dec.format("OEM information",              dos_header.oem_info)) + "\n"  \
        + (format_hex.format("Address of optional header:",
                             dos_header.addressof_new_exeheader)) + "\n"  \
        + ("") + "\n"

    header_str += ("\n== Header ==") + "\n"

    char_str = " - ".join([str(chara).split(".")[-1]
                          for chara in header.characteristics_list])

    header_str += (format_str.format("Signature:",
                                     "".join(map(chr, header.signature)))) + "\n"  \
        + (format_str.format("Machine:",                 str(header.machine))) + "\n"  \
        + (format_dec.format("Number of sections:",      header.numberof_sections)) + "\n"  \
        + (format_dec.format("Time Date stamp:",         header.time_date_stamps)) + "\n"  \
        + (format_dec.format("Pointer to symbols:",
                             header.pointerto_symbol_table)) + "\n"  \
        + (format_dec.format("Number of symbols:",       header.numberof_symbols)) + "\n"  \
        + (format_dec.format("Size of optional header:",
                             header.sizeof_optional_header)) + "\n"  \
        + (format_str.format("Characteristics:",         char_str)) + "\n"  \
        + ("")

    dll_char_str = " - ".join([str(chara).split(".")[-1]
                              for chara in optional_header.dll_characteristics_lists])
    subsystem_str = str(optional_header.subsystem).split(".")[-1]

    header_str += ("\n== Optional Header ==\n")
    magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"

    header_str += (format_str.format("Magic:", magic)) + "\n"  \
        + (format_dec.format("Major linker version:",
                             optional_header.major_linker_version)) + "\n"  \
        + (format_dec.format("Minor linker version:",
                             optional_header.minor_linker_version)) + "\n"  \
        + (format_dec.format("Size of code:",
                             optional_header.sizeof_code)) + "\n"  \
        + (format_dec.format("Size of initialized data:",
                             optional_header.sizeof_initialized_data)) + "\n"  \
        + (format_dec.format("Size of uninitialized data:",
                             optional_header.sizeof_uninitialized_data)) + "\n"  \
        + (format_hex.format("Entry point:",
                             optional_header.addressof_entrypoint)) + "\n"  \
        + (format_hex.format("Base of code:",
                             optional_header.baseof_code)) + "\n"
    if magic == "PE32":
        header_str += (format_hex.format("Base of data",
                                         optional_header.baseof_data)) + "\n"
    header_str += (format_hex.format("Image base:",
                                     optional_header.imagebase)) + "\n"  \
        + (format_hex.format("Section alignment:",
                             optional_header.section_alignment)) + "\n"  \
        + (format_hex.format("File alignment:",
                             optional_header.file_alignment)) + "\n"  \
        + (format_dec.format("Major operating system version:",
                             optional_header.major_operating_system_version)) + "\n"  \
        + (format_dec.format("Minor operating system version:",
                             optional_header.minor_operating_system_version)) + "\n"  \
        + (format_dec.format("Major image version:",
                             optional_header.major_image_version)) + "\n"  \
        + (format_dec.format("Minor image version:",
                             optional_header.minor_image_version)) + "\n"  \
        + (format_dec.format("Major subsystem version:",
                             optional_header.major_subsystem_version)) + "\n"  \
        + (format_dec.format("Minor subsystem version:",
                             optional_header.minor_subsystem_version)) + "\n"  \
        + (format_dec.format("WIN32 version value:",
                             optional_header.win32_version_value)) + "\n"  \
        + (format_hex.format("Size of image:",
                             optional_header.sizeof_image)) + "\n"  \
        + (format_hex.format("Size of headers:",
                             optional_header.sizeof_headers)) + "\n"  \
        + (format_hex.format("Checksum:",
                             optional_header.checksum)) + "\n"  \
        + (format_str.format("Subsystem:",                      subsystem_str)) + "\n"  \
        + (format_str.format("DLL Characteristics:",            dll_char_str)) + "\n"  \
        + (format_hex.format("Size of stack reserve:",
                             optional_header.sizeof_stack_reserve)) + "\n"  \
        + (format_hex.format("Size of stack commit:",
                             optional_header.sizeof_stack_commit)) + "\n"  \
        + (format_hex.format("Size of heap reserve:",
                             optional_header.sizeof_heap_reserve)) + "\n"  \
        + (format_hex.format("Size of heap commit:",
                             optional_header.sizeof_heap_commit)) + "\n"  \
        + (format_dec.format("Loader flags:",
                             optional_header.loader_flags)) + "\n"  \
        + (format_dec.format("Number of RVA and size:",
                             optional_header.numberof_rva_and_size)) + "\n"  \
        + ("")

    return header_str


def print_data_directories(binary):
    data_directories_str = "\n== Data Directories ==\n"
    data_directories = binary.data_directories

    f_title = "|{:<24} | {:<10} | {:<10} | {:<8} |"
    f_value = "|{:<24} | 0x{:<8x} | 0x{:<8x} | {:<8} |"
    data_directories_str += (f_title.format("Type",
                             "RVA", "Size", "Section")) + "\n"

    for directory in data_directories:
        section_name = directory.section.name if directory.has_section else ""
        data_directories_str += (f_value.format(str(directory.type).split('.')
                                                [-1], directory.rva, directory.size, section_name)) + "\n"
    data_directories_str += ("")
    return data_directories_str


def print_sections(binary):
    sections_str = "\n== Sections ==\n"
    sections = binary.sections

    f_title = "|{:<10} | {:<16} | {:<16} | {:<18} | {:<16} | {:<9} | {:<9}"
    f_value = "|{:<10} | 0x{:<14x} | 0x{:<14x} | 0x{:<16x} | 0x{:<14x} | {:<9.2f} | {:<9}"
    sections_str += (f_title.format("Name", "Offset", "Size",
                                    "Virtual Address", "Virtual size", "Entropy", "Flags")) + "\n"

    for section in sections:
        flags = ""
        for flag in section.characteristics_lists:
            flags += str(flag).split(".")[-1] + " "
        sections_str += (f_value.format(section.name, section.offset, section.size,
                                        section.virtual_address, section.virtual_size, section.entropy, flags)) + "\n"
    sections_str += ("")
    return sections_str


def print_symbols(binary):
    symbols_str = "\n== Symbols ==\n"
    symbols = binary.symbols
    if len(symbols) > 0:
        f_title = "|{:<20} | {:<10} | {:<8} | {:<8} | {:<8} | {:<13} |"
        f_value = u"|{:<20} | 0x{:<8x} | {:<14} | {:<10} | {:<12} | {:<13} |"

        symbols_str += (f_title.format("Name", "Value", "Section number",
                                       "Basic type", "Complex type", "Storage class"))
        for symbol in symbols:
            section_nb_str = ""
            if symbol.section_number <= 0:
                section_nb_str = str(PE.SYMBOL_SECTION_NUMBER(
                    symbol.section_number)).split(".")[-1]
            else:
                try:
                    section_nb_str = symbol.section.name
                except Exception:
                    section_nb_str = "section<{:d}>".format(
                        symbol.section_number)

            symbols_str += (f_value.format(
                symbol.name[:20],
                symbol.value,
                section_nb_str,
                str(symbol.base_type).split(".")[-1],
                str(symbol.complex_type).split(".")[-1],
                str(symbol.storage_class).split(".")[-1])) + "\n"

    return symbols_str


def print_imports(binary, resolve=False):
    imports_str = "\n== Imports ==\n"
    imports = binary.imports

    for import_ in imports:
        if resolve:
            import_ = lief.PE.resolve_ordinals(import_)
        imports_str += (import_.name) + "\n"
        entries = import_.entries
        f_value = "  {:<33} 0x{:<14x} 0x{:<14x} 0x{:<16x}"
        for entry in entries:
            imports_str += (f_value.format(entry.name, entry.data,
                                           entry.iat_value, entry.hint)) + "\n"
    return imports_str


def print_tls(binary):
    tsl_str = "\n== TLS ==\n"
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"

    tls = binary.tls
    callbacks = tls.callbacks
    tsl_str += (format_hex.format("Address of callbacks:",
                tls.addressof_callbacks)) + "\n"
    if len(callbacks) > 0:
        tsl_str += ("Callbacks:") + "\n"
        for callback in callbacks:
            tsl_str += ("  " + hex(callback))+"\n"

    tsl_str += (format_hex.format("Address of index:",  tls.addressof_index)) + "\n" \
        + (format_hex.format("Size of zero fill:", tls.sizeof_zero_fill)) + "\n" \
        + ("{:<33} 0x{:<10x} 0x{:<10x}".format("Address of raw data:",
                                               tls.addressof_raw_data[0], tls.addressof_raw_data[1])) + "\n" \
        + (format_hex.format("Size of raw data:",  len(tls.data_template))) + "\n" \
        + (format_hex.format("Characteristics:",   tls.characteristics)) + "\n"
    return tsl_str


def print_relocations(binary):
    relocations_str = "\n== Relocations ==\n"
    relocations = binary.relocations
    relocations_num = 0

    for rel in relocations:
        relocations_num += 1

    relocations_str += "Number: "+str(relocations_num) + "\n"
    return relocations_str


def print_export(binary):
    export_str = "\n== Exports ==\n"
    exports = binary.get_export()
    entries = exports.entries
    f_value = "{:<20} 0x{:<10x} 0x{:<10x} 0x{:<6x} 0x{:<6x} 0x{:<10x}"
    export_str += (f_value.format(exports.name, exports.export_flags, exports.timestamp,
                                  exports.major_version, exports.minor_version, exports.ordinal_base)) + "\n"
    entries = sorted(entries, key=lambda e: e.ordinal)
    for entry in entries:
        extern = "[EXTERN]" if entry.is_extern else ""
        export_str *= ("  {:<20} {:d} 0x{:<10x} {:<13}".format(
            entry.name[:20], entry.ordinal, entry.address, extern)) + "\n"
    return export_str


def print_debug(binary):
    debugs = binary.debug
    debug_str = ("\n== Debug ({}) ==\n".format(len(debugs)))
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    for debug in debugs:
        debug_str += (format_hex.format("Characteristics:",     debug.characteristics)) + "\n" \
            + (format_hex.format("Timestamp:",           debug.timestamp)) + "\n" \
            + (format_dec.format("Major version:",       debug.major_version)) + "\n" \
            + (format_dec.format("Minor version:",       debug.minor_version)) + "\n" \
            + (format_str.format("type:",
                                 str(debug.type).split(".")[-1])) + "\n" \
            + (format_hex.format("Size of data:",        debug.sizeof_data)) + "\n" \
            + (format_hex.format("Address of raw data:", debug.addressof_rawdata)) + "\n" \
            + (format_hex.format("Pointer to raw data:",
               debug.pointerto_rawdata)) + "\n"

        if debug.has_code_view:
            code_view = debug.code_view
            cv_signature = code_view.cv_signature

            if cv_signature in (lief.PE.CODE_VIEW_SIGNATURES.PDB_70, lief.PE.CODE_VIEW_SIGNATURES.PDB_70):
                sig_str = " ".join(
                    map(lambda e: "{:02x}".format(e), code_view.signature))
                debug_str += (format_str.format("Code View Signature:",
                                                str(cv_signature).split(".")[-1])) + "\n" \
                    + (format_str.format("Signature:", sig_str)) + "\n" \
                    + (format_dec.format("Age:", code_view.age)) + "\n" \
                    + (format_str.format("Filename:", code_view.filename)) + "\n"

        if debug.has_pogo:
            pogo = debug.pogo
            sig_str = str(pogo.signature).split(".")[-1]
            debug_str += (format_str.format("Signature:", sig_str)) + "\n" \
                + ("Entries:") + "\n"
            for entry in pogo.entries:
                debug_str += ("    {:<20} 0x{:x} ({:d})".format(
                    entry.name, entry.start_rva, entry.size)) + "\n"

    return debug_str


def print_signature(binary):
    signature_str = ""
    format_str = "{:<33} {:<30}"
    format_dec = "{:<33} {:<30d}"
    for signature in binary.signatures:
        signature_str += (signature) + "\n"

    return signature_str


def print_rich_header(binary):
    rich_header_str = "\n== Rich Header ==\n"
    header = binary.rich_header
    rich_header_str += ("Key: 0x{:08x}".format(header.key)) + "\n"

    for entry in header.entries:
        rich_header_str += ("  - ID: {:04x} Build ID: {:04x} Count: {:d}".format(entry.id,
                                                                                 entry.build_id, entry.count)) + "\n"

    return rich_header_str


def print_load_configuration(binary):
    config_str = "\n== Load Configuration ==\n"
    format_str = "{:<45} {:<30}"
    format_hex = "{:<45} 0x{:<28x}"
    format_dec = "{:<45} {:<30d}"

    config = binary.load_configuration
    if config == None:
        return config_str

    config_str += (format_dec.format("Characteristics:",
                                     config.characteristics)) + "\n" \
        + (format_dec.format("Timedatestamp:",
                             config.timedatestamp)) + "\n" \
        + (format_dec.format("Major version:",
                             config.major_version)) + "\n" \
        + (format_dec.format("Minor version:",
                             config.minor_version)) + "\n" \
        + (format_hex.format("Global flags clear:",
                             config.global_flags_clear)) + "\n" \
        + (format_hex.format("Global flags set:",
                             config.global_flags_set)) + "\n" \
        + (format_dec.format("Critical section default timeout:",
                             config.critical_section_default_timeout)) + "\n" \
        + (format_hex.format("Decommit free block threshold:",
                             config.decommit_free_block_threshold)) + "\n" \
        + (format_hex.format("Decommit total free threshold:",
                             config.decommit_total_free_threshold)) + "\n" \
        + (format_hex.format("Lock prefix table:",
                             config.lock_prefix_table)) + "\n" \
        + (format_hex.format("Maximum allocation size:",
                             config.maximum_allocation_size)) + "\n" \
        + (format_hex.format("Virtual memory threshold:",
                             config.virtual_memory_threshold)) + "\n" \
        + (format_hex.format("Process affinity mask:",
                             config.process_affinity_mask)) + "\n" \
        + (format_hex.format("Process heap flags:",
                             config.process_heap_flags)) + "\n" \
        + (format_hex.format("CSD Version:",                      config.csd_version)) + "\n" \
        + (format_hex.format("Reserved 1:",                       config.reserved1)) + "\n" \
        + (format_hex.format("Edit list:",                        config.editlist)) + "\n" \
        + (format_hex.format("Security cookie:",
                             config.security_cookie)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV0):
        config_str += (format_hex.format("SE handler table:", config.se_handler_table)) + "\n" \
            + (format_dec.format("SE handler count:", config.se_handler_count))

    if isinstance(config, lief.PE.LoadConfigurationV1):
        flags_str = " - ".join(map(lambda e: str(e).split(".")
                               [-1], config.guard_cf_flags_list))
        config_str += (format_hex.format("GCF check function pointer:",
                                         config.guard_cf_check_function_pointer)) + "\n" \
            + (format_hex.format("GCF dispatch function pointer:",
                                 config.guard_cf_dispatch_function_pointer)) + "\n" \
            + (format_hex.format("GCF function table :",
                                 config.guard_cf_function_table)) + "\n" \
            + (format_dec.format("GCF Function count :",
                                 config.guard_cf_function_count)) + "\n" \
            + ("{:<45} {} (0x{:x})".format(
                "Guard flags:", flags_str, int(config.guard_flags))) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV2):
        code_integrity = config.code_integrity
        config_str += ("Code Integrity:") + "\n" \
            + (format_dec.format(" " * 3 + "Flags:",          code_integrity.flags)) + "\n" \
            + (format_dec.format(" " * 3 + "Catalog:",        code_integrity.catalog)) + "\n" \
            + (format_hex.format(" " * 3 + "Catalog offset:",
                                 code_integrity.catalog_offset)) + "\n" \
            + (format_dec.format(" " * 3 + "Reserved:",
                                 code_integrity.reserved)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV3):
        config_str += (format_hex.format("Guard address taken iat entry table:",
                                         config.guard_address_taken_iat_entry_table)) + "\n" \
            + (format_hex.format("Guard address taken iat entry count:",
                                 config.guard_address_taken_iat_entry_count)) + "\n" \
            + (format_hex.format("Guard long jump target table:",
                                 config.guard_long_jump_target_table)) + "\n" \
            + (format_hex.format("Guard long jump target count:",
                                 config.guard_long_jump_target_count)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV4):
        config_str += (format_hex.format("Dynamic value relocation table:",
                                         config.dynamic_value_reloc_table)) + "\n"\
            + (format_hex.format("Hybrid metadata pointer:",
                                 config.hybrid_metadata_pointer)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV5):
        config_str += (format_hex.format("GRF failure routine:",
                                         config.guard_rf_failure_routine)) + "\n"\
            + (format_hex.format("GRF failure routine function pointer:",
                                 config.guard_rf_failure_routine_function_pointer)) + "\n"\
            + (format_hex.format("Dynamic value reloctable offset:",
                                 config.dynamic_value_reloctable_offset)) + "\n"\
            + (format_hex.format("Dynamic value reloctable section:",
                                 config.dynamic_value_reloctable_section)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV6):
        config_str += (format_hex.format("GRF verify stackpointer function pointer:",
                                         config.guard_rf_verify_stackpointer_function_pointer)) + "\n"\
            + (format_hex.format("Hotpatch table offset:",
                                 config.hotpatch_table_offset)) + "\n"

    if isinstance(config, lief.PE.LoadConfigurationV7):
        config_str += (format_hex.format("Reserved 3:",
                       config.reserved3)) + "\n"

    return config_str


def print_ctor(binary):
    ctor_str = ("\n== Constructors ==\n")
    ctor_str += ("Functions: ({:d})".format(
        len(binary.ctor_functions))) + "\n"
    for idx, f in enumerate(binary.ctor_functions):
        ctor_str += ("    [{:d}] {}: 0x{:x}".format(idx,
                                                    f.name, f.address)) + "\n"
    return ctor_str


def print_exception_functions(binary):
    ex = ("\n== Exception functions ==\n")

    ex += ("Functions: ({:d})".format(len(binary.exception_functions))) + "\n"
    for idx, f in enumerate(binary.exception_functions):
        ex += ("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address)) + "\n"

    return ex


def print_functions(binary):
    fun = ("\n== Functions ==\n")

    fun += ("Functions: ({:d})".format(len(binary.functions))) + "\n"
    for idx, f in enumerate(binary.functions):
        fun += ("    [{:d}] {}: 0x{:x} ({:d} bytes)".format(
            idx, f.name, f.address, f.size)) + "\n"
    return fun


def print_delay_imports(binary):
    imp_str = "\n== Delay Imports ==\n"

    delay_imports = binary.delay_imports
    if len(delay_imports) == 0:
        return imp_str

    for imp in delay_imports:
        del_imp += (imp.name) + "\n" \
            + ("  Attribute:   {}".format(imp.attribute)) + "\n" \
            + ("  Handle:      0x{:x}".format(imp.handle)) + "\n" \
            + ("  IAT:         0x{:x}".format(imp.iat)) + "\n" \
            + ("  Names Table: 0x{:x}".format(imp.names_table)) + "\n" \
            + ("  Bound IAT:   0x{:x}".format(imp.biat)) + "\n" \
            + ("  Unload IAT:  0x{:x}".format(imp.uiat)) + "\n" \
            + ("  Timestamp:   0x{:x}".format(imp.timestamp)) + "\n"
        for entry in imp.entries:
            del_imp += ("    {:<25} 0x{:08x}: 0x{:010x} - 0x{:x}".format(entry.name,
                                                                         entry.value, entry.iat_value, entry.hint)) + "\n"
    return imp_str
