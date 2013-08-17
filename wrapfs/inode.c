	/*
	* Copyright (c) 1998-2011 Erez Zadok
	* Copyright (c) 2009	   Shrikar Archak
	* Copyright (c) 2003-2011 Stony Brook University
	* Copyright (c) 2003-2011 The Research Foundation of SUNY
	*
	* This program is free software; you can redistribute it and/or modify
	* it under the terms of the GNU General Public License version 2 as
	* published by the Free Software Foundation.
	*/
	#include <linux/xattr.h>
	#include <linux/cred.h>
	#include <linux/crypto.h>
	#include <linux/scatterlist.h>
	#include <linux/fs_struct.h>

	#include "wrapfs.h"

	const char *HAS_INT_XATTR = "user.has_integrity";
	const char *INT_VAL_XATTR = "user.integrity_val";
	const char *INT_TYPE_XATTR = "user.integrity_type";

	const char *H_ATTR = "user.hash_type";
	const char *DEFAULT_ALGO = "md5";
	const char *key = "helloworld";

	static int wrapfs_create(struct inode *dir, struct dentry *dentry,
			 int mode, struct nameidata *nd)
	{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path, saved_path;
	int alloc_size = 1024;
	char *buf = kmalloc(alloc_size, GFP_KERNEL);
	char *fbuf = kmalloc(alloc_size, GFP_KERNEL);
	struct vfsmount *mnt = NULL;
	struct file *filp = NULL;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	pathcpy(&nd->path, &saved_path);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/*********************************************************/
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	__initialize_with_null(buf, alloc_size);
	__initialize_with_null(fbuf, alloc_size);
	err = vfs_getxattr(lower_parent_dentry, HAS_INT_XATTR, buf, alloc_size);
	if (err == -ENODATA) {
		err = 0;
		goto out;
	}
	if (strlen(buf) > 0 && strcmp(buf, "0") == 0) {
	#ifdef DEBUG
		printk(KERN_INFO "parent does not have the has_integrity flag set to 1\n");
	#endif
		err = 0;
		goto out;
	}
	#ifdef DEBUG
	UDBG;
	printk(KERN_INFO "parent's has_integrity set to 1.Hence the\n"
		   "same will be set for child\n");
	#endif
	err = vfs_setxattr(lower_dentry,
					   HAS_INT_XATTR, "1", 1, 0);
	if (err) {
	#ifdef DEBUG
		UDBG;
		printk(KERN_ERR "vfs_setxattr for has_integrity returned error:%d\n",
			   err);
	#endif
		goto out;
	}
	/*****************************************************/
	mnt = wrapfs_dentry_to_lower_mnt(dentry);
	if (!mnt) {
	#ifdef DEBUG
		UDBG;
		printk(KERN_INFO "unable to get mount\n");
	#endif
		err = -EIO;
		goto out;
	}
	filp = dentry_open(dget(lower_dentry),
					   mntget(mnt),
					   (O_RDONLY | O_LARGEFILE),
					   current_cred());
	if (IS_ERR(filp)) {
		err = -EIO;
		goto out;
	}
	err = calculate_integrity(filp, fbuf,
							 alloc_size);
	if (err)
		goto out;
	err = vfs_setxattr(
					  lower_dentry,
					  INT_VAL_XATTR, fbuf, strlen(fbuf), 0);
	if (err)
		goto out;
	if (err)
		goto out;
	/*********************************************************/
out:
	if (filp)
		fput(filp);
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

	static int wrapfs_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
	{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(old_dentry->d_inode);
	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			   lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = wrapfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  wrapfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
	}

	static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
	{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = wrapfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_unlink(lower_dir_inode, lower_dentry);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		  wrapfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	static int wrapfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
	{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	static int wrapfs_mkdir(struct inode *dir,
				struct dentry *dentry, int mode)
	{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	int alloc_size = 1024;
	char *buf = kmalloc(alloc_size, GFP_KERNEL);

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, wrapfs_lower_inode(dir)->i_nlink);
	/*****************************************************/
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}
	__initialize_with_null(buf, alloc_size);
	err = vfs_getxattr(lower_parent_dentry,
				HAS_INT_XATTR, buf,
				PAGE_SIZE);
	if (err == -ENODATA) {
		err = 0;
		goto out;
	}
	if (strlen(buf) > 0 && strcmp(buf, "0") == 0) {
		err = 0;
		goto out;
	}

	/*
	 As dir just set xattr to 1. NO calculation of integrity is required.
	 */
	err = vfs_setxattr(dentry, HAS_INT_XATTR, "1", 1, 0);

	if (err)
		goto out;
	/******************************************************/
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
	{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	static int wrapfs_mknod(struct inode *dir,
					struct dentry *dentry,
					int mode,
					dev_t dev)
	{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	/*
	* The locking rules in wrapfs_rename are complex.
	* We could use a simpler
	* superblock-level name-space lock for renames and copy-ups.
	*/
	static int wrapfs_rename(struct inode *old_dir,
			 struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
	{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
					  lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
	}

	static int wrapfs_readlink(struct dentry *dentry,
					   char __user *buf, int bufsiz)
	{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
		!lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
							buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
	}

	static void *wrapfs_follow_link(struct dentry *dentry,
							struct nameidata *nd)
	{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = wrapfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
	}

	/* this @nd *IS* still used */
	static void wrapfs_put_link(struct dentry *dentry, struct nameidata *nd,
				void *cookie)
	{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
	}

	static int wrapfs_permission(struct inode *inode, int mask)
	{
	struct inode *lower_inode;
	int err;

	lower_inode = wrapfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
	}

	static int wrapfs_setattr(struct dentry *dentry, struct iattr *ia)
	{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = wrapfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = wrapfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	wrapfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
	}
	/******************************************************/
	int calculate_integrity(struct file *filp,
						char *ibuf,
						int ilen)
	{
	int r = -1 , ret = -1;
	ssize_t vfs_read_retval = 0;
	loff_t file_offset = 0;
	mm_segment_t oldfs = get_fs();

	char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	struct scatterlist sg;
	struct crypto_hash *tfm = NULL;
	struct hash_desc desc;
	char *algo = kmalloc(1024, GFP_KERNEL);
	if (!algo) {
		ret = -ENOMEM;
		goto out;
	}
	__initialize_with_null(algo, 1024);

#ifdef EXTRA_CREDIT
	ret = vfs_getxattr(filp->f_path.dentry,
				 INT_TYPE_XATTR,
				 algo,
				 1024);
	if (ret <= 0)
		__initialize_with_null(algo, 1024);

#endif
	if (*algo == '\0')
		strcpy(algo, DEFAULT_ALGO);


	if (!buf)
		goto out;
	__initialize_with_null(ibuf, ilen);

	if (!filp->f_op->read) {
		r = -2;
		goto out;
	}
	filp->f_pos = 0;
	set_fs(KERNEL_DS);

	tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		r = -EINVAL;
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	if (crypto_hash_digestsize(tfm) > ilen) {
		r = -EINVAL;
		goto out;
	}
	crypto_hash_setkey(tfm, key, strlen(key));
	ret = crypto_hash_init(&desc);
	if (ret) {
		r = ret;
		goto out;
	}
	sg_init_table(&sg, 1);
	file_offset = 0;
	do {
		vfs_read_retval = vfs_read(filp, buf, PAGE_SIZE, &file_offset);

		if (vfs_read_retval < 0) {
			ret = vfs_read_retval;
			goto out;
		}
		sg_set_buf(&sg, (u8 *)buf, vfs_read_retval);
		ret = crypto_hash_update(&desc, &sg, sg.length);

		if (ret) {
			r = ret;
			goto out;
		}
		if (vfs_read_retval < ksize(buf))
			break;
	} while (1);
	ret = crypto_hash_final(&desc, ibuf);
	if (ret) {
		r = ret;
		goto out;
	}
out:
	kfree(buf);
	kfree(algo);
	if (!IS_ERR(tfm))
		crypto_free_hash(tfm);
	set_fs(oldfs);
	return ret;
	}
#ifdef EXTRA_CREDIT
	static int
	is_valid_intigrity_type(const char *algo) {
	struct crypto_hash *tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
	int ret = 0;
	if (IS_ERR(tfm))
		ret = -EINVAL;

	return ret;
	}
#endif
/*
The part that goes here is part of HW2. The methods wrapfs_(set|get|remove|list)
xattr are written in line with the smimlar methods from the module ecryptfs
*/
int
wrapfs_setxattr(struct dentry *dentry,
					const char *name,
					const void *value,
				size_t size, int flags)
	{
	int rc = 0;
	char tval = *((char *)value);
	struct dentry *lower_dentry;

	int alloc_size = 1024;
	char *buf = kmalloc(alloc_size, GFP_KERNEL);
	char *fbuf = kmalloc(alloc_size, GFP_KERNEL);
#ifdef EXTRA_CREDIT
	char *tbuf = NULL;
		int s = size;
#endif
	struct file *filp = NULL;
	struct vfsmount *mnt = NULL;

	if (!buf || !fbuf) {
		rc = -ENOMEM;
		goto out;
	}
	__initialize_with_null(buf, alloc_size);
	__initialize_with_null(fbuf, alloc_size);

	lower_dentry = wrapfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	if (strcmp(name, INT_VAL_XATTR) == 0) {
		rc = -EACCES;
		goto out;
	}
#ifdef EXTRA_CREDIT
	if (strcmp(name, INT_TYPE_XATTR) == 0) {
		if (current_uid() != 0) {
			rc = -EACCES;
			goto out;
		}
		tbuf = kmalloc(s+1, GFP_KERNEL);
		strncpy(tbuf, value, s);
		*(tbuf+s) = '\0';
		rc = is_valid_intigrity_type(tbuf);
		if (rc) {
			rc = -EINVAL;
			goto out;
		}
		if (S_ISDIR(dentry->d_inode->i_mode)) {
			rc = vfs_setxattr(
					lower_dentry,
					HAS_INT_XATTR, "1", 1, flags);
			if (rc)
				goto out;
			goto set;
		}

		mnt = wrapfs_dentry_to_lower_mnt(dentry);
		if (!mnt) {
			rc = -EIO;
			goto out;
		}
		filp = dentry_open(dget(lower_dentry),
						   mntget(mnt),
						   (O_RDONLY | O_LARGEFILE),
						   current_cred());
		if (IS_ERR(filp)) {
			rc = -EIO;
			goto out;
		}
		rc = vfs_setxattr(lower_dentry,
						  name, value, size, flags);
		if (rc)
			goto out;
		rc = calculate_integrity(filp, fbuf,
								 alloc_size);
		if (rc)
			goto out;

		rc = vfs_setxattr(
						  lower_dentry,
						  HAS_INT_XATTR, "1", 1, flags);
		if (rc)
			goto out;

		rc = vfs_setxattr(
				  lower_dentry,
				  INT_VAL_XATTR, fbuf,
				strlen(fbuf), flags);
		if (rc)
			goto out;

		goto out;

	}
#endif
	if (strcmp(name, HAS_INT_XATTR) == 0) {
		if (current_uid() != 0) {
			rc = -EACCES;
			goto out;
		}
		if (tval == '0') {
			if (S_ISDIR(dentry->d_inode->i_mode)) {
				rc = 0;
				goto set;
			}
			mutex_lock(&lower_dentry->d_inode->i_mutex);
			rc = lower_dentry->d_inode->i_op->getxattr(
					  lower_dentry,
					  INT_VAL_XATTR, buf,
					  alloc_size);
			mutex_unlock(&lower_dentry->d_inode->i_mutex);
			if (rc == -ENODATA)
				goto set;

			if (!lower_dentry->d_inode->i_op->removexattr) {
				rc = -EOPNOTSUPP;
				goto out;
			}
			mutex_lock(&lower_dentry->d_inode->i_mutex);
			rc = lower_dentry->d_inode->i_op->removexattr(
					  lower_dentry,
					  INT_VAL_XATTR);
			mutex_unlock(&lower_dentry->d_inode->i_mutex);

#ifdef EXTRA_CREDIT
			mutex_lock(&lower_dentry->d_inode->i_mutex);
			rc = lower_dentry->d_inode->i_op->removexattr(
					  lower_dentry,
					  INT_TYPE_XATTR);
			mutex_unlock(&lower_dentry->d_inode->i_mutex);
#endif

		} else if (tval == '1') {
			if (S_ISDIR(dentry->d_inode->i_mode)) {
				rc = 0;
				goto set;
			}

			mnt = wrapfs_dentry_to_lower_mnt(dentry);
			if (!mnt) {
				rc = -EIO;
				goto out;
			}
			filp = dentry_open(dget(lower_dentry),
					   mntget(mnt),
					   (O_RDONLY | O_LARGEFILE),
					   current_cred());
			if (IS_ERR(filp)) {
				rc = -EIO;
				goto out;
			}
			rc = calculate_integrity(filp, fbuf,
						 alloc_size);
			if (rc)
				goto out;
			rc = vfs_setxattr(
					  lower_dentry,
					  INT_VAL_XATTR,
						fbuf,
						strlen(fbuf),
						flags);
			if (rc)
				goto out;
		} else {
			rc = -EINVAL;
			goto out;
		}
	} /*end if (strcmp(name, HAS_INT_XATTR) == 0)*/
set:
	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
out:
#ifdef EXTRA_CREDIT
		kfree(tbuf);
#endif
		kfree(buf);
		kfree(fbuf);
	if (filp)
		fput(filp);
	return rc;
}

static ssize_t
	wrapfs_getxattr_lower(struct dentry *lower_dentry,
					  const char *name,
						void *value,
					  size_t size)
{
	int rc = 0;
	if (!lower_dentry->d_inode->i_op->getxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->getxattr(
								   lower_dentry,
								   name, value,
									size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

ssize_t
wrapfs_getxattr(struct dentry *dentry,
				const char *name,
				void *value,
				size_t size)
{
	return wrapfs_getxattr_lower(wrapfs_dentry_to_lower(dentry),
								 name,
								value, size);
}

static ssize_t
wrapfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = wrapfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->listxattr(
				lower_dentry,
				list, size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static int
wrapfs_removexattr(struct dentry *dentry, const char *name)
	{
	int rc = 0;
	struct dentry *lower_dentry;
#ifdef EXTRA_CREDIT
	struct vfsmount *mnt = NULL;
	int alloc_size = 1024;
	char *fbuf = kmalloc(alloc_size, GFP_KERNEL);
	struct file *filp = NULL;
#endif
	lower_dentry = wrapfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	if (strcmp(name, HAS_INT_XATTR) == 0) {
		if (current_uid() != 0) {
			rc = -EACCES;
			goto out;
		}
		mutex_lock(&lower_dentry->d_inode->i_mutex);
		rc = lower_dentry->d_inode->i_op->removexattr(
								  lower_dentry,
								INT_VAL_XATTR);
#ifdef EXTRA_CREDIT
		rc = lower_dentry->d_inode->i_op->removexattr(
				lower_dentry,
				INT_TYPE_XATTR);
#endif
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
	}
	if (strcmp(name, INT_VAL_XATTR) == 0) {
		rc = -EACCES;
		goto out;
	}
#ifdef EXTRA_CREDIT
	if (strcmp(name, INT_TYPE_XATTR) == 0) {
		if (current_uid() != 0) {
			rc = -EACCES;
			goto out;
		}
		if (S_ISDIR(dentry->d_inode->i_mode)) {
			rc = 0;
			goto rem;
		}

		mnt = wrapfs_dentry_to_lower_mnt(dentry);
		if (!mnt) {
			rc = -EIO;
			goto out;
		}
		filp = dentry_open(dget(lower_dentry),
						   mntget(mnt),
						   (O_RDONLY | O_LARGEFILE),
						   current_cred());
		if (IS_ERR(filp)) {
			rc = -EIO;
			goto out;
		}
		mutex_lock(&lower_dentry->d_inode->i_mutex);
		rc = lower_dentry->d_inode->i_op->removexattr(
							lower_dentry,
							name);
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
		if (rc)
			goto out;

		rc = calculate_integrity(filp, fbuf,
								 alloc_size);
		if (rc)
			goto out;

		rc = vfs_setxattr(lower_dentry,
				INT_VAL_XATTR, fbuf,
				strlen(fbuf), 0);
		if (rc)
			goto out;

		goto out;
	}
rem:
	if (filp)
		fput(filp);
#endif
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
#ifdef EXTRA_CREDIT
		kfree(fbuf);
#endif
	return rc;
}
#ifdef EXTRA_CREDIT
int
sym_setxattr(struct dentry *dentry,
			 const char *name,
			 const void *value,
			size_t size, int flags)
	{
	int rc = 0;
	struct dentry *lower_dentry;
	lower_dentry = wrapfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
out:
	return rc;
}

static int
	sym_removexattr(struct dentry *dentry, const char *name)
	{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = wrapfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}
#endif
	const struct inode_operations wrapfs_symlink_iops = {
	.readlink	= wrapfs_readlink,
	.permission	= wrapfs_permission,
	.follow_link	= wrapfs_follow_link,
	.setattr	= wrapfs_setattr,
	.put_link	= wrapfs_put_link,
	#ifdef EXTRA_CREDIT
	.setxattr = sym_setxattr,
	.getxattr = wrapfs_getxattr,
	.listxattr = wrapfs_listxattr,
	.removexattr = sym_removexattr,
	#endif
	};

	const struct inode_operations wrapfs_dir_iops = {
	.create		= wrapfs_create,
	.lookup		= wrapfs_lookup,
	.link		= wrapfs_link,
	.unlink		= wrapfs_unlink,
	.symlink	= wrapfs_symlink,
	.mkdir		= wrapfs_mkdir,
	.rmdir		= wrapfs_rmdir,
	.mknod		= wrapfs_mknod,
	.rename		= wrapfs_rename,
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,

	.setxattr = wrapfs_setxattr,
	.getxattr = wrapfs_getxattr,
	.listxattr = wrapfs_listxattr,
	.removexattr = wrapfs_removexattr,
	};

	const struct inode_operations wrapfs_main_iops = {
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,

	.setxattr = wrapfs_setxattr,
	.getxattr = wrapfs_getxattr,
	.listxattr = wrapfs_listxattr,
	.removexattr = wrapfs_removexattr,
	};
