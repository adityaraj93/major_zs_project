if [ $# -eq 1 ]
then
	gcc nt_3_1.c -lpcap && sudo ./a.out $1
elif [ $# -eq 0 ]
then
	gcc nt_3_1.c -lpcap && sudo ./a.out
else
	echo "Usage: ./compile.sh [pcap-filename]"
fi
