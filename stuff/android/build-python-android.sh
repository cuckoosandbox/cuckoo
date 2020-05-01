#!/usr/bin/env bash
# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# This script is for building the Python interpeter used for Android
# malware analysis with cuckoo.
#
# NOTE: Make sure you have a stable internet connection while using
# this script.

usage="
$(basename "$0") device_arch - Build the Python interpreter for Android.

Arguments:

  device_arch   CPU architecture of the target Android device.
"
python_version=e09359112e250268eca209355abeb17abf822486
frida_version=6c9fc24f6e8004d90aa21b4707d4c2877c3cccf8
host_arch=x86_64

script_dir="$(cd "$(dirname "$0")" && pwd)"

# Get command line argument
target_arch=$1
if [ -z "$target_arch" ]; then
  echo "ERROR: target architecture is not specified. supported archs:" \
  "(x86, x86_64, arm, arm64)." >&2
  echo "$usage" >&2
  exit 1
else
  case "$target_arch" in
    x86|x86_64|arm|arm64)
      ;;
    *)
      echo "ERROR: Unsupported architecture. choose from: " \
      "(x86, x86_64, arm, arm64)." >&2
      echo "$usage" >&2
      exit 1
      ;;
  esac
fi

# Initialize working directories.
tmpdir=$(cd $(mktemp -d "tmp.XXXX"); pwd)
mkdir build &> /dev/null
builddir=$(cd build; pwd)

if [ -f "$builddir/android-${target_arch}.tar.gz" ]; then
  echo "Nothing to do! Python interpreter is already built for ${target_arch}."
  exit 0
fi

# Download NDK r21
export ANDROID_NDK_ROOT="$builddir/android-ndk-r21"
if [ ! -d "$ANDROID_NDK_ROOT" ]; then
  echo "Downloading Android Native development kit r21."
  wget -P "$tmpdir" "https://dl.google.com/android/repository/android-ndk-r21-linux-${host_arch}.zip"
  unzip "$tmpdir/android-ndk-r21-linux-${host_arch}.zip" -d "$builddir"
else
  echo "Found NDK r21!"
fi

# Download Python v3.7 from source
python_src_dir="$builddir/cpython"
if [ ! -d "$python_src_dir" ]; then
  echo "Downloading Python 3.7 from source."
  git -C "$builddir" clone --branch 3.7 "https://github.com/python/cpython.git"
else
  echo "Found Python already fetched!"
  echo ""
fi
cd "$python_src_dir"
git checkout "$python_version"
git reset --hard "$python_version"

# Building Python for host machine
echo "Buildig the Python interpreter for host machine"
sleep 2

if [ ! -d "$builddir/host-python" ]; then
  ./configure
  make
  make install DESTDIR="$builddir/host-python"
  make clean
else
  echo "Build target already exists."
fi

# Building Python for android target
echo "Building the Python interpreter for Android ${target_arch}..."
sleep 2

if [ $target_arch == "arm" ]; then
  if [ ! -f "$script_dir/python-lld-compatibility.patch" ]; then
    echo "Couldn't find python-lld-compatibility.patch"
    exit 1
  fi
  patch -sNp1 --dry-run < "$script_dir/python-lld-compatibility.patch"
  if [ $? -eq 0 ]; then
    patch -p1 < "$script_dir/python-lld-compatibility.patch"
  fi
  autoreconf -ivf
fi

# Create config.site
CONFIG_SITE="config.site"
echo "ac_cv_file__dev_ptmx=yes" > $CONFIG_SITE
echo "ac_cv_file__dev_ptc=no" >> $CONFIG_SITE

android_toolroot="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-${host_arch}/bin"
android_api=21  # Compilation breaks for API < 21
if [ $target_arch == "x86" ]; then
  compiler_triplet="i686-linux-android"
elif [ $target_arch == "x86_64" ]; then
  compiler_triplet="x86_64-linux-android"
elif [ $target_arch == "arm" ]; then
  compiler_triplet="armv7a-linux-androideabi"
  tooltriplet="arm-linux-androideabi"
elif [ $target_arch == "arm64" ]; then
  compiler_triplet="aarch64-linux-android"
fi
if [ -z "$tooltriplet" ]; then
  tooltriplet="$compiler_triplet"
fi

export PATH="$builddir/host-python/usr/local/bin:$PATH"

./configure CC="$android_toolroot/${compiler_triplet}${android_api}-clang" \
  CXX="$android_toolroot/${compiler_triplet}${android_api}-clang++" \
  CPP="$android_toolroot/${compiler_triplet}${android_api}-clang -E" \
  LD="${android_toolrot}/$tooltriplet-ld" \
  AR="$android_toolroot/$tooltriplet-ar" \
  AS="$android_toolroot/$tooltriplet-as" \
  STRIP="$android_toolroot/$tooltriplet-strip" \
  RANLIB="$android_toolroot/$tooltriplet-ranlib" \
  READELF="$android_toolroot/$tooltriplet-readelf" \
  OBJCOPY="$android_toolroot/$tooltriplet-objcopy" \
  OBJDUMP="$android_toolroot/$tooltriplet-objdump" \
  CFLAGS="-fPIC" \
  CXXFLAGS="$CFLAGS" \
  LDFLAGS="-fuse-ld=lld" \
  CONFIG_SITE="$CONFIG_SITE" \
  --prefix=/usr --host="$compiler_triplet" \
  --build="${host_arch}-linux-gnu" --disable-ipv6

make
py_android_builddir="$tmpdir/android-${target_arch}-python"
make install DESTDIR="$py_android_builddir"
make clean

find "$py_android_builddir" -depth -name '__pycache__' -exec rm -rf {} ';'
find "$py_android_builddir" -name '*.py[co]' -exec rm -f {} ';'
find "$py_android_builddir" -name '*.[oa]' -exec rm -f {} ';'
rm -rf "$py_android_builddir/usr/share"
rm -f "$py_android_builddir/usr/bin/python3.7m"
rm -rf "$py_android_builddir/usr/lib/python3.7/test"

# Download Frida from source
frida_src_dir="$builddir/frida"
if [ ! -d "$frida_src_dir" ]; then
  echo "Downloading Frida from source."
  git -C "$builddir" clone --recurse-submodules "https://github.com/frida/frida.git"
else
  echo "Found Frida already fetched!"
fi
git -C "$frida_src_dir" checkout "$frida_version"
cd "$frida_src_dir"

# Build Frida's Python bindings
echo "Building Frida's Python bindings -- https://github.com/frida/frida"
sleep 2

make FRIDA_HOST="android-$target_arch" \
  PYTHON_INCDIR="$py_android_builddir/usr/include/python3.7m" \
  PYTHON_NAME="python3.7" \
  "build/tmp_thin-android-$target_arch/frida-python3.7/.frida-stamp"

cp -r "$frida_src_dir/build/frida_thin-android-$target_arch/lib/python3.7/site-packages/"* "$py_android_builddir/usr/lib/python3.7/site-packages"
if [ ! $? -eq 0 ]; then
    make clean
    echo "Failed to build Frida.. Exiting.." >&2
    exit 1
fi

# Create compressed output
cd "$py_android_builddir"
rm -rf "usr/include"
export GZIP=-9
tar cfz "android-${target_arch}.tar.gz" usr/
mv "android-${target_arch}.tar.gz" "$builddir"

# Delete temp directory.
rm -rf "$tmpdir"

echo ""
echo "Done!"
echo "Interpreter is built under -> $builddir/android-${target_arch}.tar.gz"
