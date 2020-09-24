export PATH=/media/asennyey/Storage/Exploits/test-deprecate/csmith/src/:$PATH
function mkDiff(){
    mkdir $1
    cd $1
    $PIN/pin -t $TRACER64/Tracer.so -srcreg -memread -- ../../$date_1-out > DebugPrints.txt
    $TRACE2ASCII/trace2ascii trace.out > ascii.txt
    awk -F' ' '{sub(/;/, "", $5); print $5}' ascii.txt > newAscii.txt
}
source $NEW_DIR/setup.sh;
date_1=$(date +%s);

cd "tmp";
csmith > $date_1.c;
gcc ./$date_1.c -I$(pwd)/csmith/runtime -o $date_1-out;

mkdir $date_1;
cd $date_1;
mkDiff first $(pwd) & mkDiff second $(pwd);

wait $!;

cd ..;

diff ./first/newAscii.txt ./second/newAscii.txt;