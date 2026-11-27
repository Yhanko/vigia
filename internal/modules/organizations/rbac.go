package organizations

// Role values matching migrations/00002_identity_orgs_audit.sql CHECK constraint.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

// Permission identifiers from README §10.5 (deny by default).
type Permission string

const (
	PermOrgRead              Permission = "organization:read"
	PermOrgUpdate            Permission = "organization:update"
	PermOrgDelete            Permission = "organization:delete"
	PermOrgTransferOwnership Permission = "organization:transfer_ownership"
	PermMemberRead           Permission = "member:read"
	PermMemberInvite         Permission = "member:invite"
	PermMemberRemove         Permission = "member:remove"
	PermMemberUpdateRole     Permission = "member:update_role"
	PermTeamRead             Permission = "team:read"
	PermTeamManage           Permission = "team:manage"
	PermProjectRead          Permission = "project:read"
	PermProjectCreate        Permission = "project:create"
	PermProjectUpdate        Permission = "project:update"
	PermProjectDelete        Permission = "project:delete"
	PermAPIKeyRead           Permission = "api_key:read"
	PermAPIKeyCreate         Permission = "api_key:create"
	PermAPIKeyRevoke         Permission = "api_key:revoke" //nolint:gosec // G101: RBAC permission identifier, not a credential
	PermAuditRead            Permission = "audit:read"
)

var rolePermissions = map[string]map[Permission]struct{}{
	RoleOwner: {
		PermOrgRead: {}, PermOrgUpdate: {}, PermOrgDelete: {}, PermOrgTransferOwnership: {},
		PermMemberRead: {}, PermMemberInvite: {}, PermMemberRemove: {}, PermMemberUpdateRole: {},
		PermTeamRead: {}, PermTeamManage: {},
		PermProjectRead: {}, PermProjectCreate: {}, PermProjectUpdate: {}, PermProjectDelete: {},
		PermAPIKeyRead: {}, PermAPIKeyCreate: {}, PermAPIKeyRevoke: {},
		PermAuditRead: {},
	},
	RoleAdmin: {
		PermOrgRead: {}, PermOrgUpdate: {},
		PermMemberRead: {}, PermMemberInvite: {}, PermMemberRemove: {}, PermMemberUpdateRole: {},
		PermTeamRead: {}, PermTeamManage: {},
		PermProjectRead: {}, PermProjectCreate: {}, PermProjectUpdate: {}, PermProjectDelete: {},
		PermAPIKeyRead: {}, PermAPIKeyCreate: {}, PermAPIKeyRevoke: {},
		PermAuditRead: {},
	},
	RoleMember: {
		PermOrgRead:     {},
		PermMemberRead:  {},
		PermTeamRead:    {},
		PermProjectRead: {}, PermProjectCreate: {}, PermProjectUpdate: {},
		PermAPIKeyRead: {},
	},
	RoleViewer: {
		PermOrgRead:     {},
		PermMemberRead:  {},
		PermTeamRead:    {},
		PermProjectRead: {},
	},
}

// HasPermission reports whether role grants perm (deny by default).
func HasPermission(role string, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	_, allowed := perms[perm]
	return allowed
}

// IsValidRole reports whether role is one of the four canonical RBAC roles.
func IsValidRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}

// CanInviteRole enforces that admins cannot invite owners and only owner/admin can invite.
func CanInviteRole(actorRole, invitedRole string) bool {
	if !HasPermission(actorRole, PermMemberInvite) {
		return false
	}
	return invitedRole == RoleAdmin || invitedRole == RoleMember || invitedRole == RoleViewer
}

// CanModifyMember enforces RBAC anti-escalation rules (TASKS 1.2 Bloco 5):
//   - Only owner/admin with PermMemberUpdateRole/PermMemberRemove can act.
//   - Nobody may promote or modify their own role.
//   - Admin cannot remove or demote an owner, and cannot promote anyone to owner.
//   - Promoting to owner is done exclusively via TransferOwnership.
func CanModifyMember(actorRole, actorUserID, targetRole, targetUserID, newRole string) bool {
	if actorUserID == targetUserID {
		return false
	}
	if !HasPermission(actorRole, PermMemberUpdateRole) {
		return false
	}
	if newRole == RoleOwner {
		return false
	}
	if newRole != "" && !IsValidRole(newRole) {
		return false
	}
	if actorRole == RoleAdmin && targetRole == RoleOwner {
		return false
	}
	return true
}
