The top level scripts in this folder are used for auto-generating VMF header information.
The subfolders contain python scripts that are helpers for VMF and need to actually be compiled.

A pre-compiled version of these scripts is provided under bin.  To recompile these scripts, run pyinstaller from from script directory with resulting executable output to bin.  For example, to build the klee python output tools:
```
cd process_klee_output
pyinstaller --onefile process_klee_output.py --distpath ../bin
```

The top level make files will install the contents of scripts/bin.