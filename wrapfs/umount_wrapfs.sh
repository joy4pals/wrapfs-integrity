echo "Wrapfs will now be un-mounted"

LOWER_MNTPT=/n/scratch
UPPER_MNTPT=/tmp

umount $UPPER_MNTPT
umount $LOWER_MNTPT
rmmod wrapfs
echo "Wrapfs unmounted successfully.!!"
