rm -r build/

mkdir build && cd build

cmake ..
cmake --build .

cd ..

cp out/metamorphic.exe /media/sf_SharedDrive/
cp out/metamorphic_encrypted.exe /media/sf_SharedDrive/