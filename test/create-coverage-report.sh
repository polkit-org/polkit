#!/bin/sh

TOTAL_ACTUAL=0
TOTAL_COVERED=0
TOTAL_SOURCE=0

P=$(dirname $0)/..

MODULE=$1
shift


echo "=============================================================================="
echo "Test coverage for $MODULE:"
echo "=============================================================================="

while [ $# -gt 0 ] ; do
    SOURCE=`cat $P/$1 |wc -l`
    ACTUAL=`grep -v "        -:" $P/$1.gcov  |wc -l`
    NOT_COVERED=`grep "    #####:" $P/$1.gcov  |wc -l`
    COVERED=$(($ACTUAL - $NOT_COVERED))
    PERCENT=$((100 * $COVERED / $ACTUAL))

    TOTAL_SOURCE=$(($TOTAL_SOURCE + $SOURCE))
    TOTAL_ACTUAL=$(($TOTAL_ACTUAL + $ACTUAL))
    TOTAL_COVERED=$(($TOTAL_COVERED + $COVERED))

    echo -n "$1"

    n=${#1}
    while [ $n -lt 55 ] ; do
        echo -n " "
        n=$(($n + 1))
    done

    echo -n " : "

    if [ $PERCENT -lt 10 ] ; then
        echo -n "  $PERCENT%"
    elif [ $PERCENT -lt 100 ] ; then
        echo -n " $PERCENT%"
    else
        echo -n "100%"
    fi

    echo " ($COVERED of $ACTUAL)"

    shift
done

TOTAL_PERCENT=$((100 * $TOTAL_COVERED / $TOTAL_ACTUAL))

echo
echo "Source lines          : $TOTAL_SOURCE"
echo "Actual statements     : $TOTAL_ACTUAL"
echo "Executed statements   : $TOTAL_COVERED"
echo "Test coverage         : $TOTAL_PERCENT%"
echo
