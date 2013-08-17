Overview
-------------
This assignment involves a security policy to be implemented as a stackable file system based on wrapfs. This policy empowers the root to monitor particular files and directories for intrusion detection bt setting values to some xattrs. As a result of this, while opening the value of this xattr is matched with the current calculated checksum of the file and and if they do not match then it conveys that the file has been tampered and the sysem does not alloe opening the file. 

Mounting the filesystem
---------------------------

The code of the filesystem is developed by modifying the existing code of the fs/wrapfs/* files and hence the source can befound there in. This module needs to be compiled using the command:
make install modules
from the top of the linux source tree. To install the module along with the wrapfs and ext3 a custom shell script exists at the fs/wrapfs named 
mount_wrapfs.sh. This script 
1. Inserts the compiled kernel module (wrapfs.ko) into the kernel.
2. mounts the ext3 at /n/scratch/
3. mounts wrapfs on top of ext3 at /tmp
This code has been written in line with the professor Zaddok's script at /usr/src/hw2-tests/j-ltp.sh. Once the wrapfs is mounted the changes made at the /tmp/* goes through the wrapfs layer and it preparees the system for the security policy we want to implement.
There is also the complimentary script called umount-wrapfs.sh which does the opposite of what mount_wrapfs.sh does.
1. unmounts the wrapfs at /tmp
2. unmount the ext3 at /n/scratch
3. removes the module wrapfs.ko

Security Policy and how it works
------------------------------------
	Files
	-----
		setting the xattr user.has_integrity
		------------------------------------
In order to trigger the integrity check for a file, the file must reside in the sub-tree of the files and directories rooted at the mount point of the wrapfs(In case you are using the script mount_wrapfs.sh it is /tmp). For the file the root hand picks to check the integrity of, he must set the  xattr  user.has_integrity to 1. This can be done using any userlevel tool. This is one of the examples enabling integrity check on file test.txt:
#cd /tmp
#touch test.txt
#setfattr -n user.has_integrity -v 1 test.txt

-The user.has_integrity xattr takes the values 0 or 1 only.
-Can be set or unset only by ROOT. 
Absence of the xattr or prsence with the value 0, makes a particular file a NON-CANDIDATE for integrity checks(i.e NO integrity checks). In case the user.has_integrity is set to 1, any changes written to the file makes the system recalculate the integrity during the file close. 

Policy and design principles:

Setting the xattr user.has_integrity=1 does a sequence of things:
a> It calculate the integrity of the file based on its current contents.
b> creates an extended attribute user.integrity_val for the file.
c> stores the file integrity as part of the xattr user.integrity_val.
NO ONE can create the xattr user.integrity_val or set or reset the value, not even the root. This done only by the kernel based on the attribute user.has_integrity. Setting the value of user.has_integrity to 0 or removing this totally removes the xattr user.integrity_val. 
There is never a state when the value of user.has_integrity is set to 1 and the xattr user.integrity_val does not exist. This is ensured by calculating the checksum of the file and setting the value of the user.integrity before setting the user.has_integrity to 1.
There can be some corner cases to these as well. As wrapfs is sitting on top of the ext3 therefore the same files can be accessed in two ways: one is through /tmp/* path which makes the files accessable through the wrapfs layer and the other is through /n/scratch/*. If some someone accesses the file from the botton layer and alters the xattr user.integrity_val then a perfectly valid file will be rendered unusable through the wrapfs layer because the current checksum of the file will not match what is stored in the xattr user.integrity_val. 
There can be other cases such as the setting the xattr user.has_integrity of the file to 0 from the lower layer. This can make an important file bypass the integrity check and recalculation when alteren from the wrapfs layer.
Some other cases of inconsistencies are in case of  partial failures. If some portions of the code executes before a failure, then the system aborts on the error without processing any further line of code and at the same time without undoing the the parts of the code that has already been executeed. This left to user to to check if everything is in a state he/she wants it to be and if not he she should  try to bring it to the same. This is done to reduce the overhead of processing more than required from the kernel because in this case the kernel has to keep a track of the state of the system when it all stared and this is best done at the user level.
		Removing the xattrs
		--------------------
The xattr user.integrity_val cannot be removed even by the root. The xattr.user.has_integrity caan be removed though but only by the ROOT. 
In order to maintain  the consistency of the system, the xattr user.integrity_val is removed by the kernel before removing the xattr user.has_integrity. Removing the xattr should make the file a non-candidate for intergrity checks during opening the file and recalculation during the file close on writes. The inconsistencies that might occur due to the modifications and removal from the lower filesystem instead of the wrapfs such as removing the user.integrity_val while user.has_integrity is still present is not handled.

		Getting and Listing Attributes
		-------------------------------
There are no restrictions on getting and listings of the xattrs. Anyone and everyone can get or list all the xattrs present on a file. 

	
	Directories
	-----------
The root can also set the xattrs user.has_integrity on a directory. Now directories are special. Setting this value to 1 on a directory makes all the files/directories under that directory candidates for integrity check. This is implemented as part of the crate function. During the creation of a new file or directory the system checks whether the user.has_integrity value of its parent directory is set to 1. If so, then the same is set to 1 for this one and if it is a file this calls an additional function to calculate the integrity and storing it in the user.integrity_val and in case the chlild is a directory just set the user.has_integrity to 1. 
There are some corner cases such as :
a>setting the user.has_integrity of a dir to 1 and then create some directories and files under it and then setting the value of the parent directory to 0 or removing it altogether. In this case the kernel does not perform any recursive operation and the user.has_integrity val of the children are left as they were before unsetting the value of the parent. 
b>Create a diectory and some files and directories under it. Then set the value of the parent as 1. IN this case the kernel does not go hunting for the children and setting the values for them as 1. But for any new file/ dir created henceforth under this parent will have the xattr has_integrity set accordingly based on the additional book keeping that needs to be done in case of files.


EXTRA_CREDIT
-------------
For the extra credit the ROOT is also given the priveledge of choosing the checksum algorithm. This is done by setting the xattr user.integrity_type.
There are initial checks to see that the root sets the value to something that the kernel has support for. hence, setting the value of the xattr might result in error in case:
-An user other that the root tries to set the xattr user.integrity_type.
-The value choosen is not a valid checksum type of the kernel does not support it at the time.
#setfattr -n user.integrity_type -v abc /tmp/test.txt
should return an error because abc is not a valid checksum type. Nonethe less
#setfattr -n user.integrity_type -v sha1 /tmp/test.txt
should succeed.
If this attribute isnot set then the system calculates the checksum based on the default type which is chosen to be md5. 
Also some other decisions are taken to maintain the integrity of the system.Setting the value of the user.integrity_type to something valid also sets the xattr user.has_integrity to 1 and in case this is regular file, the integrity of hte file contents will be calculated based on new checksum and the value will be stored in the xattr user.integrity_val. 
changing the value to something else will also recalculate the checksum for regular file.
Removing the xattr user.integrity_type will invoke a recalculation of the check sum of the regular file based on hte default md5. In case the xattr user.has_integrity is removed or set to 0, xattr user.integrity_type and user.integrity_val are deleted.
The same corner cases applies as if the user changes the attributes of the file from the lower the file goes into an inconsistent state and this case ha s not been handled.
