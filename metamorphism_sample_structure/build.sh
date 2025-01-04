rm -r build/

mkdir build && cd build

cmake ..
cmake --build .

cd ..

cp out/loader_engine_stripped.exe /media/sf_SharedDrive/