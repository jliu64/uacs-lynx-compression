export PATH=$(pwd)/csmith/src/:$PATH
function mkDiff(){
    mkdir $1
    cd $1
    $PIN/pin -t $TRACER64/Tracer.so -srcreg -memread -- ../../$date_1-out > DebugPrints.txt
    $TRACE2ASCII/trace2ascii trace.out > ascii.txt
    awk -F' ' '{sub(/;/, "", $5); print $5}' ascii.txt > newAscii.txt
}

cd tmp;
set -e
for i in `seq 0 10`;
do
    source $NEW_DIR/setup.sh;
    date_1=$(date +%s);
    csmith > $date_1.c;
    gcc ./$date_1.c -I$(pwd)/../csmith/runtime -o $date_1-out > /dev/null 2>&1;
    
    mkdir $date_1;
    cd $date_1;
    mkDiff first $(pwd) & mkDiff second $(pwd);

    wait $!;

    cd ..;

    diff ./first/newAscii.txt ./second/newAscii.txt;

    cd ..;

    source $OLD_DIR/setup.sh;

    date_2=$(date +%s);
    mkdir $date_2;
    cd $date_2;
    mkDiff first $(pwd) & mkDiff second $(pwd);

    wait $!;

    cd ..;

    diff ./first/newAscii.txt ./second/newAscii.txt;

    cd ..;

    dateDiffName=$date_1"."$date_2"-diff.txt"

    diff $date_1/first/newAscii.txt $date_2/first/newAscii.txt > $dateDiffName;
    diff $date_1/first/newAscii.txt $date_2/second/newAscii.txt >> $dateDiffName;
    diff $date_1/second/newAscii.txt $date_2/first/newAscii.txt >> $dateDiffName;
    diff $date_1/second/newAscii.txt $date_2/second/newAscii.txt >> $dateDiffName;
done