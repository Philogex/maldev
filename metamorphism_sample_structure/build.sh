./clean.sh

mkdir build && cd build
cmake ..
cmake --build .

cp out/metamorphic.exe ../out/
cp out/metamorphic_stripped.exe ../out/
cp out/metamorphic_disasm.txt ../out/
cp out/metamorphic_strings.txt ../out/
cp out/metamorphic_ir.ir ../out/
cp out/metamorphic.exe /media/sf_SharedDrive/