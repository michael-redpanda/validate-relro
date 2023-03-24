# Validate Full RELRO

This script will check for the existance of the `GNU_RELRO` program header
and for the existance of the `.got.plt` section.  It will verify that:
* the `.got.plt` section is within the `GNU_RELRO` program header
* All symbols in `.got.plt` are contained within the `GNU_RELRO` program header
