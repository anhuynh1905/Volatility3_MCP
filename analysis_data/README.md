# Analysis Data Directory

This directory is mounted to `/app/02_working` inside the container.

Place your memory dumps and forensic images here:

## Supported Formats
- `.raw` - Raw memory dumps
- `.vmem` - VMware memory files
- `.dmp` - Windows crash dumps
- `.lime` - Linux Memory Extractor files
- `.mem` - Generic memory files
- `.bin` - Binary memory images
- `.img` - Disk/memory images
- `.001` - Split memory files
- `.elf` - ELF files

## Example Structure
```
analysis_data/
├── case1/
│   ├── memdump.raw
│   └── notes.txt
├── case2/
│   ├── windows_vm.vmem
│   └── malware_sample.exe
└── lab_exercises/
    ├── MemLabs-Lab6/
    │   └── MemoryDump_Lab6.raw
    └── practice_dumps/
```

## Access from Container
Your files will be available at `/app/02_working/` inside the container and accessible to both MCP servers for analysis.