from stap2stix import get_syscalls_and_cwd, get_name, get_containerid, is_on_whitelist


def test_get_syscalls_and_cwd():
    syscalls, cwd = get_syscalls_and_cwd("test.stap")
    assert syscalls == ['Wed Mar  4 10:57:01 2020.057387 containerid|python2.7@7efde9781e37[1351] execve("/usr/local/bin/sh", ["sh", "-c", "/tmp4jmNPr/.buildwatch.sh"], ["LANG=en_US", "SHELL=/bin/sh", "LANGUAGE=en_US:", "PWD=/root", "LOGNAME=root", "HOME=/root", "PATH=/usr/local/bin:/usr/bin:/bin"]) = -2 (ENOENT)',
                        'Wed Mar  4 10:57:01 2020.059064 |sh@7f3dee9baf43[1351] mmap2(0x0, 26882, PROT_READ, MAP_PRIVATE, 6, 0) = 0x7f3deebbe000']
    assert cwd == "/tmp4jmNPr"


def test_get_name():
    line = 'Wed Mar  4 10:57:01 2020.057387 containerid|python2.7@7efde9781e37[1351] execve("/usr/local/bin/sh", ["sh", "-c", "/tmp4jmNPr/.buildwatch.sh"], ["LANG=en_US", "SHELL=/bin/sh", "LANGUAGE=en_US:", "PWD=/root", "LOGNAME=root", "HOME=/root", "PATH=/usr/local/bin:/usr/bin:/bin"]) = -2 (ENOENT)'
    classifier_name = "processes_created"
    name = get_name(line, classifier_name)
    assert name == "python2.7"

    line = 'Wed Mar  4 09:57:16 2020.115639 |npm@7f0f9dbd8777[1359] connect(14, {AF_INET, 127.0.0.53, 53}, 16) = 0'
    classifier_name = "domains"
    name = get_name(line, classifier_name)
    assert name == "npm"

    line = 'Wed Mar  4 09:57:16 2020.199683 |npm@7f0f9dbd8dae[1362] openat(AT_FDCWD, "/root/.npm/registry.npmjs.org/querystring/.cache.json.1255587233", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 17'
    classifier_name = "files_written"
    name = get_name(line, classifier_name)
    assert name == "/root/.npm/registry.npmjs.org/querystring/.cache.json.1255587233"

    line = '/tmp4jmNPr/Wed Mar  4 09:57:16 2020.105590 |npm@7f0f9dbd8dae[1353] openat(AT_FDCWD, \"/dev/null\", O_RDONLY|O_CLOEXEC) = 13'
    classifier_name = "files_read"
    name = get_name(line, classifier_name)
    assert name == "/dev/null"

    line = '/tmp4jmNPr/Wed Mar  4 09:57:17 2020.225519 |npm@7f0f9d8e7d47[1361] unlink(\"/tmp/npm-1353-143e3fd3/registry.npmjs.org/ajv/-/ajv-6.12.0.tgz\") = 0'
    classifier_name = "files_read"
    name = get_name(line, classifier_name)
    assert name == "/tmp/npm-1353-143e3fd3/registry.npmjs.org/ajv/-/ajv-6.12.0.tgz"


def test_get_containerid():
    line = "Wed Mar  4 10:57:01 2020.056990 123abc|python2.7@7efde9483ca3[1351] set_robust_list(0x7efde9ca7a20, 24) = 0"
    id = get_containerid(line)
    assert id == "123abc"


def test_is_on_whitelist():
    line = 'Wed Mar  4 09:57:18 2020.065415 |npm@7f0f9d8e5775[1359] stat("/root/.npm/_locks", 0x7f0f9b7d0e10) = -2 (ENOENT)'
    value = is_on_whitelist(line)
    assert value

    line = 'Wed Mar  4 09:57:18 2020.065443 |npm@7f0f9dbd82b7[1359] write(12, "\001\0\0\0\0\0\0\0", 8) = 8'
    value = is_on_whitelist(line)
    assert not value

