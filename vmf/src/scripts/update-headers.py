#! /usr/bin/python3

import subprocess

cpp_files_cmd = "find . -name *.*pp"
java_files_cmd = "find . -name *.java"
html_files_cmd = "find . -name *.html"
jsp_files_cmd = "find . -name *.jsp"
cmake_files_cmd = "find . -name CMakeLists.txt -o -name *.cmake"
header_divider = "====="

def getContents(fp):
    """
    Get the contents of a given file, ignoring any header delimited by
    `header_divider`.
    """
    contents = ""
    in_header = None

    # remove header
    for line in fp:
        if (in_header == False): # header has been cleared
            contents += line

        if (header_divider in line and in_header == None): # header start 
            in_header = True
        elif (header_divider in line and in_header): # header end 
            in_header = False
        elif (in_header == None): # no header at all
            contents += line

    
    return contents

def getPaths(cmd):
    # collect all the source files
    paths = subprocess.run(cmd.split(),
        encoding='UTF-8', stdout=subprocess.PIPE).stdout

    trimmed_paths = [x for x in paths.split() 
        if x and '/submodules/' not in x and \
           '/build/' not in x and \
           '/external/' not in x]

    return trimmed_paths

def updateHeaders(header, paths):
    for path in paths:
        print (f"-- Updating headers for {path}... ", end='')
        fp = open(path, "r")
        contents = getContents(fp)
        fp.close()

        fp = open(path, "w")
        fp.write(header + contents)
        fp.close()
        print("done")

if __name__ == "__main__":
    # retrieve the latest header comments
    c_header_fp = open("./vmf/src/scripts/c-header", "r")
    c_header = c_header_fp.read()
    c_header_fp.close()

    cmake_header_fp = open("./vmf/src/scripts/cmake-header", "r")
    cmake_header = cmake_header_fp.read()
    cmake_header_fp.close()

    html_header_fp = open("./vmf/src/scripts/html-header", "r")
    html_header = html_header_fp.read()
    html_header_fp.close()

    trimmed_cpp_paths = getPaths(cpp_files_cmd)
    trimmed_cmake_paths = getPaths(cmake_files_cmd)
    trimmed_java_paths = getPaths(java_files_cmd)
    trimmed_html_paths = getPaths(html_files_cmd)
    trimmed_jsp_paths = getPaths(jsp_files_cmd)

    updateHeaders(c_header, trimmed_cpp_paths)
    updateHeaders(c_header, trimmed_java_paths)
    updateHeaders(cmake_header, trimmed_cmake_paths)
    updateHeaders(html_header, trimmed_html_paths)
    updateHeaders(html_header, trimmed_jsp_paths)

    print("***Headers must be MANUALLY updated for .xml, .js, and .css (as not all of these files are ours)***")
