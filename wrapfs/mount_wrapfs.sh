echo "This script will now mount wrapfs on top of existing ext3"
insmod wrapfs.ko 
SCRATCH_DEV=/dev/sdb1
lowertype=ext3
LOWER_MNTPT=/n/scratch
UPPER_MNTPT=/tmp

mkfs -t $lowertype -q $SCRATCH_DEV
mount -t $lowertype -o user_xattr $SCRATCH_DEV $LOWER_MNTPT
mount -t wrapfs -o user_xattr $LOWER_MNTPT $UPPER_MNTPT

echo "file systems mounted successfully.."
