//go:build darwin && cgo

package vpncore

/*
#include <errno.h>
#include <sys/acl.h>

static int vpncore_acl_has_write(int fd) {
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return -errno;
	}
	acl_entry_t entry;
	int entry_id = ACL_FIRST_ENTRY;
	for (;;) {
		int result = acl_get_entry(acl, entry_id, &entry);
		if (result < 0) {
			if (entry_id == ACL_NEXT_ENTRY && errno == EINVAL) {
				break;
			}
			int saved = errno;
			acl_free(acl);
			return -saved;
		}
		entry_id = ACL_NEXT_ENTRY;
		acl_tag_t tag;
		if (acl_get_tag_type(entry, &tag) != 0) {
			int saved = errno;
			acl_free(acl);
			return -saved;
		}
		if (tag != ACL_EXTENDED_ALLOW) {
			continue;
		}
		acl_permset_t perms;
		if (acl_get_permset(entry, &perms) != 0) {
			int saved = errno;
			acl_free(acl);
			return -saved;
		}
		if (acl_get_perm_np(perms, ACL_WRITE_DATA) == 1 ||
		    acl_get_perm_np(perms, ACL_APPEND_DATA) == 1 ||
		    acl_get_perm_np(perms, ACL_DELETE) == 1 ||
		    acl_get_perm_np(perms, ACL_DELETE_CHILD) == 1 ||
		    acl_get_perm_np(perms, ACL_WRITE_ATTRIBUTES) == 1 ||
		    acl_get_perm_np(perms, ACL_WRITE_EXTATTRIBUTES) == 1 ||
		    acl_get_perm_np(perms, ACL_WRITE_SECURITY) == 1 ||
		    acl_get_perm_np(perms, ACL_CHANGE_OWNER) == 1) {
			acl_free(acl);
			return 1;
		}
	}
	acl_free(acl);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"syscall"
)

func checkWriteACL(_ string, fd int) error {
	result := int(C.vpncore_acl_has_write(C.int(fd)))
	switch {
	case result == 0:
		return nil
	case result == 1:
		return fmt.Errorf("write-capable ACL entry")
	case result == -int(syscall.ENOENT):
		// macOS reports ENOENT for an existing file that has no extended ACL.
		return nil
	default:
		return fmt.Errorf("inspect ACL: %w", syscall.Errno(-result))
	}
}
