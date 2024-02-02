#/bin/bash

print_help()
{
   # Display Help
   echo "Syntax: clean.sh [-m|h]"
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

rm -r "$BUILD_PATH"
mkdir "$BUILD_PATH" -p
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=arm-none-eabi-gcc -DCMAKE_CXX_COMPILER=arm-none-eabi-g++ -G Ninja -S "$PROJECT_PATH" -B "$BUILD_PATH"
