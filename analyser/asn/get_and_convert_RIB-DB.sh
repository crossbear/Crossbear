# $1 == curr_ipasndat == DB used for scanning
# $2 == file name path of backup current DB
# $3 == folder to curr_ipasndat
#
# first change into dir of this script
#cd $4 
set -x

if [[ -f "$1" ]] 
then
	echo 'Saving RIB DB to backup'
	mv $1 $2
fi
echo 'Fetching new copy of RIB DB'
wget -q http://archive.routeviews.org/bgpdata/`date +%Y.%m`/RIBS/rib.`date +%Y%m%d`.0000.bz2 --output-document=$3curr_rib_dump.bz2
python pyasn-read-only/converter/convert_rib.py $3curr_rib_dump.bz2 $1
# remove the dump, as we dont need it anymore
rm $3curr_rib_dump.bz2
echo 'Done retrieving current RIB DB'
