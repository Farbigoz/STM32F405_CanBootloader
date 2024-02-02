#/bin/bash


print_help()
{
   # Display Help
   echo "Syntax: prog-btl.sh [-m|i|h]"
   echo "options:"
   echo "m     Module type: [cu, mpp, gks, ktrc, mec]."
   echo "i     Interface: [jlink, stlink]."
   echo "h     Print this Help."
   echo
}


unset -v module_type
unset -v interface

while getopts "m:i:h" opt; do
  case $opt in
    m) module_type=$OPTARG ;;

    i) interface=$OPTARG ;;

    h) print_help
       exit 0 ;;

    *) echo 'Error in command line parsing' >&2
       print_help
       exit 1 ;;
  esac
done

# shift "$(( OPTIND - 1 ))"

if [ -z "$module_type" ]
then
  echo "Missing -m \"module_type\". For help use flag \"-h\"."
  exit 1
fi

if [ -z "$interface" ]
then
  echo "Missing -i \"interface\". For help use flag \"-h\"."
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

case $interface in
  stlink) ;;
  jlink)  ;;

  *)  echo "Unsupported interface \"$interface\"."
      exit 1;;
esac


openocd -l "/tmp/btl_openocd.log" -c version
if [ ! -z $(grep -o 0.10. /tmp/btl_openocd.log) ]; then
  openocd_ver=10
elif [ ! -z $(grep -o 0.11. /tmp/btl_openocd.log) ]; then
  openocd_ver=11
elif [ ! -z $(grep -o 0.12. /tmp/btl_openocd.log) ]; then
  openocd_ver=12
fi


if [ "$openocd_ver" = "10" ]; then

  case $interface in
    stlink) interface_cfg="stlink_stm32f4x.cfg";;
    jlink)  interface_cfg="jlink_stm32f4x.cfg";;
  esac

elif [ "$openocd_ver" = "11" ] || [ "$openocd_ver" = "12" ]; then

  case $interface in
    stlink) interface_cfg="stlink_stm32f4x_ocd11.cfg";;
    jlink)  interface_cfg="jlink_stm32f4x_ocd11.cfg";;
  esac

else

  echo "Unsupported openocd version."
  exit 1

fi

openocd -f "./$interface_cfg" -c "tcl_port disabled" -c "gdb_port disabled" -c "tcl_port disabled" -c "program \"./cmake-build-release-$module_type/STM32F405_CanBootloader.elf\"" -c reset -c shutdown
