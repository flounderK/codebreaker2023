import argparse
import functools
import logging
import string
import os
import re

log = logging.getLogger(__file__)
if not log.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(levelname)s %(message)s")
    log.addHandler(handler)
log.setLevel(logging.DEBUG)


def batch(it, sz):
    for i in range(0, len(it), sz):
        yield it[i:i+sz]


def hexdump_str(bytevals, offset=0, bytes_per_line=16, bytegroupsize=2):
    # get max address size
    max_address = len(bytevals) + offset
    curr_addr = max_address
    address_chr_count = 0
    while curr_addr > 0:
        curr_addr = curr_addr >> 4
        address_chr_count += 1

    if address_chr_count < 8:
        address_chr_count = 8

    num_spaces = ((bytes_per_line // bytegroupsize)-1)
    # 2 chars for each byte
    hex_byte_print_size = (bytes_per_line*2) + num_spaces
    # generate a line formatstring specifying max widths
    line_fmtstr = '%%0%dx: %%-%ds  %%s' % (address_chr_count,
                                           hex_byte_print_size)
    printable_char_ints = set(string.printable[:-5].encode())

    outlines = []
    for line_num, byteline in enumerate(batch(bytevals, bytes_per_line)):
        line_bytegroups = []
        line_strchrs = ""
        addr = (line_num*bytes_per_line) + offset
        for bytegroup in batch(byteline, bytegroupsize):
            bytegroup_str = ''.join(['%02x' % i for i in bytegroup])
            line_bytegroups.append(bytegroup.hex())
            for b in bytegroup:
                # force the value to stay as a byte instead of converting
                # to an integer
                if b in printable_char_ints:
                    line_strchrs += chr(b)
                else:
                    line_strchrs += '.'
        hex_bytes = ' '.join(line_bytegroups)
        hex_bytes = hex_bytes.ljust(hex_byte_print_size, ' ')
        out_line = line_fmtstr % (addr, hex_bytes, line_strchrs)
        outlines.append(out_line)

    return '\n'.join(outlines)


def execute_output(command):

    basepath = os.getenv('HOME')
    if basepath is None:
        basepath = "/tmp"
    # create temporary file for the output
    filename = os.path.join(basepath, 'gdb_output')

    # set gdb logging
    logging_off_str = "set logging enabled off"

    gdb.execute("set logging file " + filename)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    try:
        gdb.execute("set logging enabled on")
    except:
        gdb.execute("set logging on")
        logging_off_str = "set logging off"

    # execute command
    try:
        gdb.execute(command)
    except:
        pass

    # restore normal gdb behaviour
    gdb.execute(logging_off_str)
    gdb.execute("set logging redirect off")

    # read output and close temporary file
    with open(filename, 'r') as f:
        output = f.read()

    # delete file
    os.remove(filename)

    return output


def parse_proc_maps():
    maps = execute_output("info proc mappings")
    split_maps_lines = maps.splitlines()
    start_addr_lines = [(i, s) for i, s in enumerate(split_maps_lines) if s.find('Start Addr') != -1]
    column_names_line_ind, column_names_line = start_addr_lines[0]
    if len(split_maps_lines) == column_names_line_ind + 1:
        log.debug("no mappings for session")
        return []
    column_names_line = column_names_line.strip()
    log.debug("column names line: '%s'", column_names_line)

    # column names can't really be known ahead of time without a big version table,
    # and even then it isn't very reliable. also because columns can be separated by
    # a single space and column names can also contain a space, splitting column
    # names isn't really reliable either

    col_names = ["Start Addr", "End Addr", "Size", "Offset", "Perms", "objfile"]
    col_names += [
        "\S+\s\S+",  # catchall for unk column names with a single space in them
        "\S+",  # catchall for unk column names without a single space in them
                # but after the space one so that this matches last
    ]

    col_names_pat = "(%s)" % "|".join(col_names)
    log.debug("col_names_pat: '%s'", col_names_pat)
    col_names_rexp = re.compile(col_names_pat, re.I)
    ordered_column_names = [m.groups()[0] for m in re.finditer(col_names_rexp, column_names_line)]

    colname_to_pattern_map = {
        "objfile": "(?:.+)?"
    }
    # order of columns is now known
    line_sub_patterns = []
    for col_name in ordered_column_names:
        sub_pat = colname_to_pattern_map.get(col_name, "\S+")
        sanitized_col_name = re.sub("\s", "_", col_name)
        sub_pat_with_name = "(?P<%s>%s)" % (sanitized_col_name, sub_pat)
        log.debug("adding '%s'", sub_pat_with_name)
        line_sub_patterns.append(sub_pat_with_name)

    line_pattern = "\s+".join(line_sub_patterns)
    log.debug("line_pattern: '%s'", line_pattern)
    line_rexp = re.compile(line_pattern)
    search_lines = split_maps_lines[column_names_line_ind+1:]
    maybe_matches = [re.search(line_rexp, i) for i in search_lines]
    matches = [i for i in maybe_matches if i is not None]
    if len(matches) != len(maybe_matches):
        none_inds = [i for i, s in enumerate(maybe_matches) if s is None]
        for ind in none_inds:
            log.warning("match failed on '%s'", search_lines[ind])
    return [i.groupdict() for i in matches]


def get_file_paths(directory):
    for dirpath, dirnames, filenames in os.walk(searchdir):
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def add_symbol_files_for_core(searchdir=None):

    proc_maps_entries = parse_proc_maps()
    useful_entries = []
    for e in proc_maps_entries:
        if e['objfile'] == '':
            continue
        if e['Offset'] != "0x0":
            continue
        if e['objfile'].startswith("/dev"):
            continue
        useful_entries.append(e)

    useful_entries_by_basename = {os.path.basename(e['objfile']): e for e in useful_entries}

    if searchdir is None:
        searchdir = os.getcwd()

    add_symbol_commands = []
    for path in get_file_paths(searchdir):
        basename = os.path.basename(path)
        entry = useful_entries_by_basename.get(basename)
        if entry is None:
            continue

        add_sym_command = "add-symbol-file -readnow -o %s %s" % (entry['Start_Addr'], path)
        add_symbol_commands.append(add_sym_command)

    for cmd in add_symbol_commands:
        gdb.execute(cmd)


class FuncArgsBreakPoint(gdb.Command):
    USAGE = "Usage: funcargsbp <breakpoint_name> <breakpoint addr> [[fmt-string]...[args]]"

    def __init__(self):
        super(FuncArgsBreakPoint, self).__init__("funcargsbp", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)

    def invoke(self, argstr, from_tty):
        try:
            args = argstr.split(maxsplit=2)
        except ValueError:
            raise Exception(self.USAGE)
        if len(args) < 2:
            raise Exception(self.USAGE)
        # print(args)
        bp_name, bp_addr_str = args[:2]
        bp_print_args_fmt = "\"%s\\n\"" % bp_name
        bp_print_args_spec = args[:2]
        # bp_print_args_spec[0] = '"%s"' % bp_print_args_spec[0]
        if len(args) >= 3:
            bp_print_args_fmt = ", ".join(args[2:])
            bp_print_args_fmt = bp_print_args_fmt.replace("${BPNAME}", bp_name)

        command = ""
        command += "set $BP_%s = %s\n" % (bp_name, bp_addr_str)
        command += "b *$BP_%s\n" % bp_name
        command += "set $BP_%s_bpnum = $bpnum\n" % bp_name
        command += "commands\n"
        command += "    silent\n"
        command += "    printf %s\n" % bp_print_args_fmt
        command += "    continue\n"
        command += "end\n"
        # print(command)
        gdb.execute(command, from_tty=False)

FuncArgsBreakPoint()


class SaveValBP(gdb.Command):

    def __init__(self):
        super(SaveValBP, self).__init__("savevalbp", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("addr", help="address to break and store values")
        self.parser.add_argument("displaytype", help="How to display the saved value")
        self.parser.add_argument("register", help="register to store the value of")

    def invoke(self, argstr, from_tty):
        # don't auto repeat
        self.dont_repeat()
        args = self.parser.parse_args(argstr)

SaveValBP()


def parse_gdb_cmd_args(argstr):
    # log.debug("argstr '%s'", argstr)
    gdb_evaluated_args = []
    for arg in gdb.string_to_argv(argstr):
        try:
            # try to evaluate each arg in case it is an expression first
            evaluated_arg = gdb.parse_and_eval(arg)
            string_arg = evaluated_arg.format_string()
        except gdb.error:
            # if evaluation fails just use the raw arg
            string_arg = arg
        gdb_evaluated_args.append(string_arg)
    # log.debug("gdb_evaluated_args %s", str(gdb_evaluated_args))
    return gdb_evaluated_args


class PrintBufferInHex(gdb.Command):
    def __init__(self):
        super(PrintBufferInHex, self).__init__("printbufinhex", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("addr", help="address to print buffer at", type=functools.partial(int, base=0))
        self.parser.add_argument("size", help="size of buffer", type=functools.partial(int, base=0))

    def invoke(self, argstr, from_tty):
        raw_args = parse_gdb_cmd_args(argstr)
        args = self.parser.parse_args(raw_args)
        # log.debug("address %s" % hex(args.addr))
        # log.debug("buf size %s" % hex(args.size))
        cur_infer = gdb.selected_inferior()
        mem = cur_infer.read_memory(args.addr, args.size)
        mem_bytes = mem.tobytes()
        print(mem_bytes.hex(), end='')


PrintBufferInHex()


class HexdumpBuf(gdb.Command):
    def __init__(self):
        super(HexdumpBuf, self).__init__("hexdumpbuf", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("addr", help="address to hexdump", type=functools.partial(int, base=0))
        self.parser.add_argument("size", help="size of buffer", type=functools.partial(int, base=0))

    def invoke(self, argstr, from_tty):
        raw_args = parse_gdb_cmd_args(argstr)
        args = self.parser.parse_args(raw_args)
        # log.debug("address %s" % hex(args.addr))
        # log.debug("buf size %s" % hex(args.size))
        cur_infer = gdb.selected_inferior()
        mem = cur_infer.read_memory(args.addr, args.size)
        mem_bytes = mem.tobytes()
        print(hexdump_str(mem_bytes, offset=args.addr))


HexdumpBuf()
