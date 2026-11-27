package organizations

import "testing"

func TestRBACPermissionMatrixAndAntiEscalation(t *testing.T) {
	// Deny by default for unknown role.
	if HasPermission("superadmin", PermOrgRead) {
		t.Fatal("unknown role must be denied by default")
	}

	// Viewer and Member must be denied all admin/owner actions.
	adminActions := []Permission{
		PermOrgUpdate, PermOrgDelete, PermOrgTransferOwnership,
		PermMemberInvite, PermMemberRemove, PermMemberUpdateRole,
		PermTeamManage, PermProjectDelete, PermAPIKeyCreate, PermAPIKeyRevoke, PermAuditRead,
	}
	for _, role := range []string{RoleViewer, RoleMember} {
		for _, perm := range adminActions {
			if HasPermission(role, perm) {
				t.Fatalf("role %q unexpectedly granted privileged permission %q", role, perm)
			}
		}
	}

	// Admin cannot delete org or transfer ownership (owner only).
	for _, ownerOnly := range []Permission{PermOrgDelete, PermOrgTransferOwnership} {
		if HasPermission(RoleAdmin, ownerOnly) {
			t.Fatalf("admin must not have owner-only permission %q", ownerOnly)
		}
		if !HasPermission(RoleOwner, ownerOnly) {
			t.Fatalf("owner must have permission %q", ownerOnly)
		}
	}

	// Anti-escalation guards.
	if CanInviteRole(RoleAdmin, RoleOwner) {
		t.Fatal("admin must not invite owner")
	}
	if CanInviteRole(RoleMember, RoleViewer) || CanInviteRole(RoleViewer, RoleViewer) {
		t.Fatal("member/viewer must not invite anyone")
	}
	if CanModifyMember(RoleAdmin, "u1", RoleOwner, "u2", RoleMember) {
		t.Fatal("admin must not demote owner")
	}
	if CanModifyMember(RoleAdmin, "u1", RoleOwner, "u2", "") {
		t.Fatal("admin must not remove owner")
	}
	if CanModifyMember(RoleAdmin, "u1", RoleMember, "u2", RoleOwner) {
		t.Fatal("admin must not promote anyone to owner")
	}
	if CanModifyMember(RoleAdmin, "u1", RoleAdmin, "u1", RoleOwner) {
		t.Fatal("nobody may promote themselves")
	}
	if CanModifyMember(RoleMember, "u1", RoleViewer, "u2", RoleAdmin) {
		t.Fatal("member must not change roles")
	}
	if !CanModifyMember(RoleAdmin, "u1", RoleMember, "u2", RoleAdmin) {
		t.Fatal("admin should be able to update member to admin")
	}
}
