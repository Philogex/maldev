file(REMOVE_RECURSE
  "CMakeFiles/post_build_commands"
  "out/adjacency_table.bc"
  "out/c2_handler.bc"
  "out/config.bc"
  "out/control_flow_handler.bc"
  "out/cryptor.bc"
  "out/instruction_substitutor.bc"
  "out/main.bc"
  "out/main_pass.bc"
  "out/metamorphic.exe"
  "out/metamorphic_disasm.txt"
  "out/metamorphic_ir.ir"
  "out/metamorphic_strings.txt"
  "out/metamorphic_stripped.exe"
  "out/pass_output.txt"
  "out/program.bc"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/post_build_commands.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
