./clean.sh

mkdir build && cd build
cmake ..
cmake --build .

cp out/metamorphic.exe ../out/
cp out/metamorphic.exe /media/sf_SharedDrive/