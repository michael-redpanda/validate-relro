# Validate Full RELRO

This script will check for the existance of the `GNU_RELRO` program header
and for the existance of the `.got.plt` section.  It will verify that:
* the `.got.plt` section is within the `GNU_RELRO` program header
* All symbols in `.got.plt` are contained within the `GNU_RELRO` program header


## Usage

```text
usage: validate.py [-h] binary

Program used to validate all symbols are RELRO

positional arguments:
  binary      Path to binary to examine

options:
  -h, --help  show this help message and exit
```

Simply point validate.py at the binary in question and run it.

Example output:

```json
{
  "binary": "/home/mboquard/dev/michael-redpanda/vbuild/release/clang/bin/redpanda",
  "results": {
    "relro_header": {
      "type": "GNU_RELRO",
      "offset": 107621504,
      "virtual_address": 107629696,
      "physical_address": 107629696,
      "file_size": 1066024,
      "memory_size": 1069952
    },
    "got_plt": {
      "got_plt_in_relro": true,
      "got_plt_section": {
        "number": 30,
        "header": {
          "name": ".got.plt",
          "type": "PROGBITS",
          "address": 108695392,
          "offset": 108687200,
          "size": 328,
          "entry_size": 0,
          "align": 8
        }
      },
      "got_plt_symbols": [
        {
          "offset": 108695416,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_finalize@GLIBC_2"
        },
        {
          "offset": 108695424,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_mutex_lock@GLIBC_2"
        },
        {
          "offset": 108695432,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_mutex_unlock@GLIBC_2"
        },
        {
          "offset": 108695440,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_attr_getstacksize@GLIBC_2"
        },
        {
          "offset": 108695448,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_attr_getguardsize@GLIBC_2"
        },
        {
          "offset": 108695456,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "syscall@GLIBC_2"
        },
        {
          "offset": 108695464,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_attr_init@GLIBC_2"
        },
        {
          "offset": 108695472,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_attr_destroy@GLIBC_2"
        },
        {
          "offset": 108695480,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "fprintf@GLIBC_2"
        },
        {
          "offset": 108695488,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "abort@GLIBC_2"
        },
        {
          "offset": 108695496,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_setspecific@GLIBC_2"
        },
        {
          "offset": 108695504,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "getrlimit@GLIBC_2"
        },
        {
          "offset": 108695512,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "pthread_key_create@GLIBC_2"
        },
        {
          "offset": 108695520,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "getpid@GLIBC_2"
        },
        {
          "offset": 108695528,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__errno_location@GLIBC_2"
        },
        {
          "offset": 108695536,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "dlsym@GLIBC_2"
        },
        {
          "offset": 108695544,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "dlvsym@GLIBC_2"
        },
        {
          "offset": 108695552,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_atexit@GLIBC_2"
        },
        {
          "offset": 108695560,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_begin_catch@Base"
        },
        {
          "offset": 108695568,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZSt9terminatev@Base"
        },
        {
          "offset": 108695576,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__dynamic_cast@Base"
        },
        {
          "offset": 108695584,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_end_catch@Base"
        },
        {
          "offset": 108695592,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_allocate_exception@Base"
        },
        {
          "offset": 108695600,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_free_exception@Base"
        },
        {
          "offset": 108695608,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_throw@Base"
        },
        {
          "offset": 108695616,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_rethrow@Base"
        },
        {
          "offset": 108695624,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__stack_chk_fail@GLIBC_2"
        },
        {
          "offset": 108695632,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_Unwind_Resume@GCC_3"
        },
        {
          "offset": 108695640,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_thread_atexit@Base"
        },
        {
          "offset": 108695648,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_bad_cast@Base"
        },
        {
          "offset": 108695656,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZTHN7seastar3smp3_qsE@Base"
        },
        {
          "offset": 108695664,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZTHN27permit_unsafe_log_operation5_flagE@Base"
        },
        {
          "offset": 108695672,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "__cxa_get_exception_ptr@Base"
        },
        {
          "offset": 108695680,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev@Base"
        },
        {
          "offset": 108695688,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "exp2@GLIBC_2"
        },
        {
          "offset": 108695696,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZTHN7seastar17g_current_contextE@Base"
        },
        {
          "offset": 108695704,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZSt17__throw_bad_allocv@Base"
        },
        {
          "offset": 108695712,
          "type": "R_X86_64_JUMP_SLOT",
          "value": "_ZTHN7seastar16logging_failuresE@Base"
        }
      ]
    }
  }
}

```
