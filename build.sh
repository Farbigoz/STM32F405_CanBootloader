#/bin/bash

print_help()
{
   # Display Help
   echo "Syntax: build.sh [-m|h]"
   echo "options:"
   echo "m     Module type: [cu, mpp, gks, ktrc, mec]."
   echo "h     Print this Help."
   echo
}


unset -v module_type

while getopts "m:h" opt; do
  case $opt in
    m) module_type=$OPTARG ;;

    h) print_help
       exit 0 ;;

    *) echo 'Error in command line parsing' >&2
       print_help
       exit 1 ;;
  esac
done

if [ -z "$module_type" ]
then
  echo "Missing -m \"module_type\". For help use flag \"-h\"."
  exit 1
fi

case $module_type in
  cu)   ;;
  mpp)  ;;
  gks)  ;;
  ktrc) ;;
  mec)  ;;

  *)  echo "Unknown module \"$module_type\"."
      exit 1;;
esac

PROJECT_PATH=$(dirname $(readlink -f "$0"))
BUILD_DIR="cmake-build-release-$module_type"
BUILD_PATH="$PROJECT_PATH"/"$BUILD_DIR"

export EXEC_IN_RAM=1
export MODULE_TYPE=$module_type

if [ ! -d "$BUILD_PATH" ]; then
  bash clean.sh -m $module_type
fi

#cd "$BUILD_PATH"
cmake --build "$BUILD_PATH" --target STM32F405_CanBootloader.elf -j $(nproc)
