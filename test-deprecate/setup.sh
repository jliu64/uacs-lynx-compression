if [ ! -d 'csmith' ]; then
    git clone https://github.com/csmith-project/csmith.git csmith
    cd csmith 
        ./configure
        make
    cd ..
fi

export TRACE2ASCII=$(cd ~/exploits/pin-new/source/tools/ASE-2020/Tools/trace2ascii && pwd)
export PIN=$(cd ~/exploits/pin-new && pwd)
export TRACER64=$(cd ~/exploits/pin-new/source/tools/ASE-2020/Tools/tracer/obj-intel64/ && pwd)
export NEW_DIR=$(cd ~/exploits/pin-new/source/tools/UpdatedUACS/uacs-lynx && pwd)
export OLD_DIR=$(cd ~/exploits/pin-3.7/source/tools/ScienceUpToPar/Tools && pwd)