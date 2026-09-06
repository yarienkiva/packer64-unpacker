# packer64-unpacker
Unpacker for executables packed with https://github.com/jadams/Packer64

## Usage

```bash
./packer64-unpack.py test.exe -o test.exe.out
Packer64 unpacker v1.0 - alol_re
Unpacking test.exe
Extracting to test.exe.out

md5sum test.exe.{orig,out}
5da8c98136d98dfec4716edd79c7145f  test.exe.orig
5da8c98136d98dfec4716edd79c7145f  test.exe.out
```

## Notes

Nothing groundbreaking, very basic packer (just break on WriteProcessMemory). Uses a very old compression algorithm (QuickLZ), so that's fun.
