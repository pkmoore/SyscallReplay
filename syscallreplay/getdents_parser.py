"""Code for parsing the structure returned by getdents as represented by
strace's format.  posix-omni-parser fails entirely to deal with these
structures so we fall back to manually dealing with the original line
"""

DIRENT_TYPES = {
    'DT_UNKNOWN': 0,
    'DT_FIFO': 1,
    'DT_CHR': 2,
    'DT_DIR': 4,
    'DT_BLK': 6,
    'DT_REG': 8,
    'DT_LNK': 10,
    'DT_SOCK': 12,
    'DT_WHT': 14,
}


def parse_getdents_structure(syscall_object):
    if 'getdents' not in syscall_object.name:
        raise ValueError('Received argument is not a getdents(64) syscall '
                         'object')
    if syscall_object.args[1].value == '{}':
        return []
    left_brace = syscall_object.original_line.find('{')
    right_brace = syscall_object.original_line.rfind('}')
    line = syscall_object.original_line[left_brace+1:right_brace-1]
    entries = line.split('}, {')

    tmp = []
    for i in entries:
        tmp += [i.split(', ')]
    entries = tmp
    tmp = []
    tmp_dict = {}
    for i in entries:
        for j in i:
            s = j.split('=')
            k = s[0].strip('{}')
            v = s[1]
            tmp_dict[k] = v
        tmp += [tmp_dict]
        tmp_dict = {}
    entries = tmp

    for i in entries:
        i['d_name'] = i['d_name'].lstrip('"').rstrip('"')
        try:
            i['d_type'] = DIRENT_TYPES[i['d_type']]
        except KeyError:
            raise NotImplementedError('Unsupported d_type: {}'
                                      .format(i['d_type']))
        i['d_ino'] = int(i['d_ino'])
        i['d_reclen'] = int(i['d_reclen'])
        i['d_off'] = int(i['d_off'])
    return entries
