file(REMOVE_RECURSE
  "CMakeFiles/optimizing"
  "out/adjacency_table.bc"
  "out/c2_handler.bc"
  "out/config.bc"
  "out/control_flow_handler.bc"
  "out/cryptor.bc"
  "out/instruction_substitutor.bc"
  "out/main.bc"
  "out/main_pass.bc"
  "out/pass_output.txt"
  "out/program.bc"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/optimizing.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
