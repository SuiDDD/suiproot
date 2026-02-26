if [ "$1" != "continue" ]; then
   sudo apt update
   sudo apt install -y build-essential git wget unzip
   git clone https://github.com/termux/proot.git suiproot
   cd suiproot
   wget https://www.samba.org/ftp/talloc/talloc-2.4.2.tar.gz
   wget https://dl.google.com/android/repository/android-ndk-r29-linux.zip
   tar -xvf talloc-2.4.2.tar.gz
   unzip android-ndk-r29-linux.zip
   cd ..
fi
export ROOT_DIR=$(realpath .)/suiproot
export NDK_PATH=$ROOT_DIR/android-ndk-r29
export TOOLCHAIN=$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64
export TARGET=aarch64-linux-android
export API=35
export CC=$TOOLCHAIN/bin/$TARGET$API-clang
export CXX=$TOOLCHAIN/bin/$TARGET$API-clang++
export AR=$TOOLCHAIN/bin/llvm-ar
export STRIP=$TOOLCHAIN/bin/llvm-strip
export OBJCOPY=$TOOLCHAIN/bin/llvm-objcopy
export TALLOC_DIR=$ROOT_DIR/talloc-2.4.2
cd $TALLOC_DIR
rm -rf bin
rm -f cross-answers.txt
cat <<EOF > cross-answers.txt
Checking uname sysname type: "Linux"
Checking uname release type: "6.6.30"
Checking uname machine type: "aarch64"
Checking uname version type: "#1 SMP PREEMPT_DYNAMIC"
Checking getconf LFS_CFLAGS: "OK"
Checking for large file support without additional flags: OK
Checking for -D_FILE_OFFSET_BITS=64: OK
Checking for -D_LARGE_FILES: OK
Checking for HAVE_SECURE_MKSTEMP: OK
Checking for HAVE_IFACE_IFCONF: OK
Checking for HAVE_IPV6: OK
Checking for HAVE_MREMAP: OK
Checking for working strptime: OK
Checking for gettimeofday: OK
Checking for C prototype for gettimeofday: OK
Checking for correct behavior of strtoll: NO
Checking for C99 vsnprintf: OK
Checking for HAVE_SHARED_MMAP: OK
Checking for HAVE_INCOHERENT_MMAP: NO
Checking for XSI (rather than GNU) prototype for strerror_r: NO
Checking if signal handlers return int: NO
Checking for rpath library support: NO
Checking for -Wl,--version-script support: YES
Checking for setproctitle: NO
Checking for library bsd: NO
Checking for setproctitle_init: NO
Checking for declaration of getgrent_r: NO
Checking for declaration of getgrent_r (as enum): NO
Checking for declaration of getpwent_r: NO
Checking for declaration of getpwent_r (as enum): NO
Checking C prototype for getpwent_r: NO
Checking C prototype for getgrent_r: NO
Checking for strerror_r: OK
Checking for program 'xsltproc': NO
rpath library support: NO
-Wl,--version-script support: YES
Checking correct behavior of strtoll: NO
Checking for memset_explicit: OK
Checking for declaration of memset_explicit: YES
EOF
make clean
sed -i 's/memset_explicit(dest, destsz, ch, count)/memset_explicit(dest, ch, count)/g' lib/replace/replace.c
sed -i 's/void \*memset_explicit(void \*dest, size_t destsz, int ch, size_t count)/void \*memset_explicit(void \*dest, int ch, size_t count)/g' lib/replace/replace.c
./configure --cross-compile --cross-execute="" --cross-answers=cross-answers.txt --disable-python --without-gettext --builtin-libraries=replace,talloc --disable-symbol-versions && make
if [ -f bin/default/talloc.vscript ]; then
   sed -i '/_end;/d; /_edata;/d; /__bss_start;/d' bin/default/talloc.vscript
fi
make
if [ -f bin/default/talloc.vscript ]; then
   sed -i '/_end;/d; /_edata;/d; /__bss_start;/d' bin/default/talloc.vscript
fi
make
cd ../src
sed -i '1i #include <string.h>' extension/ashmem_memfd/ashmem_memfd.c
make proot CC="$CC" OBJCOPY="$OBJCOPY" CFLAGS="-I$TALLOC_DIR -I$TALLOC_DIR/lib/replace" LOADER_32BIT=off OBJCOPY_ARCH="elf64-littleaarch64" OBJIFY='@echo "  GEN $@"; $(OBJCOPY) --input-target=binary --output-target=elf64-littleaarch64 --binary-architecture aarch64 $< $@' || true
TALLOC_OBJ=$(find $TALLOC_DIR/bin/default -name "talloc.c.*.o" | head -n 1)
REPLACE_OBJ=$(find $TALLOC_DIR/bin/default/lib/replace -name "replace.c.*.o" | head -n 1)
PROOT_OBJS=$(find . -name "*.o" ! -name "*m32*" ! -name "loader.o" ! -path "*talloc*")
$CC $PROOT_OBJS $TALLOC_OBJ $REPLACE_OBJ -o proot
$STRIP proot
file proot