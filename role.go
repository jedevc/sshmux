package main

import "github.com/charmbracelet/ssh"

// contextKey is a private type for context values stored in ssh.Context.
type contextKey string

const rolesKey contextKey = "roles"

// ContextWithRoles stores roles in an ssh.Context.
func ContextWithRoles(ctx ssh.Context, roles []string) {
	ctx.SetValue(rolesKey, roles)
}

// RolesFromContext retrieves the roles stored in an ssh.Context.
// Returns nil if no roles have been set.
func RolesFromContext(ctx ssh.Context) []string {
	v := ctx.Value(rolesKey)
	if v == nil {
		return nil
	}
	r, _ := v.([]string)
	return r
}

// G is an alias for RolesFromContext.
var G = RolesFromContext
