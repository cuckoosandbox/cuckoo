# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Jar(Package):
    """Java analysis package."""
    PATHS = [
        # Default Java installation paths.
        # See: http://www.oracle.com/technetwork/java/archive-139210.html
        ("ProgramFiles", "Java", "jre1.8.0_31", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.8.0_25", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.8.0_20", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.8.0_11", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.8.0_5", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.8.0", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_72", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_71", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_67", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_65", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_60", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_55", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_51", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_45", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_40", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_25", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_21", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_17", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_15", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_13", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_11", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_10", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_9", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_7", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_6", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_5", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_4", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_3", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_2", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0_1", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.7.0", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_45", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_43", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_41", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_39", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_38", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_37", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_35", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_34", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_33", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_32", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_31", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_30", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_29", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_27", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_26", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_25", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_24", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_23", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_22", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_21", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_20", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_19", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_18", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_17", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_16", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_15", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_14", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_13", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_12", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_11", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_10", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_7", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_6", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_5", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_4", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_3", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_2", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0_1", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre1.6.0", "bin", "java.exe"),
        # Custom paths, if user choose a custom installation path.
        ("ProgramFiles", "Java", "jre8", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre7", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jre6", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path("Java")
        class_path = self.options.get("class")

        if class_path:
            args = ["-cp", path, class_path]
        else:
            args = ["-jar", path]

        return self.execute(java, args=args)
