package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/web"
)

// ImpersonateStart lets an admin assume a target user's identity within the same
// session. The real admin id is stored on the session so it can be restored, and
// the action is audited. This handler is mounted behind the admin RBAC group, so
// the caller is always an admin/superadmin acting as themselves (you cannot start
// a nested impersonation — while impersonating, the admin routes are unreachable).
//
// Only role 'user' accounts may be impersonated, which makes privilege escalation
// impossible (you can never gain rights you didn't already have).
func (a *Auth) ImpersonateStart(w http.ResponseWriter, r *http.Request) {
	admin := MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid user id")
		return
	}
	if id == admin.ID {
		web.Error(w, http.StatusBadRequest, "self", "cannot impersonate yourself")
		return
	}
	target, err := a.Store.GetUserByID(r.Context(), id)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if target.Role != "user" {
		web.Error(w, http.StatusForbidden, "forbidden", "only standard users can be impersonated")
		return
	}
	if target.Status != "active" {
		web.Error(w, http.StatusBadRequest, "inactive", "user is not active")
		return
	}

	sessID := sessionIDFrom(r.Context())
	sess, ok := SessionFrom(r.Context())
	if !ok || sessID == "" {
		web.Error(w, http.StatusInternalServerError, "internal", "no session")
		return
	}
	if sess.ImpersonatorID != nil {
		web.Error(w, http.StatusConflict, "already_impersonating", "stop the current impersonation first")
		return
	}

	adminID := admin.ID
	next := *sess
	next.UserID = target.ID
	next.MFARequired = false
	next.ImpersonatorID = &adminID
	next.ImpersonatorEmail = admin.Email
	if err := a.saveSession(r.Context(), sessID, next); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update session")
		return
	}
	_ = a.Store.Audit(r.Context(), &target.AccountID, &adminID, "admin.impersonate_start", target.Email, clientIP(r),
		map[string]any{"target_user_id": target.ID.String()})

	web.JSON(w, http.StatusOK, map[string]any{
		"user":         toUserDTO(target),
		"impersonator": map[string]any{"id": adminID.String(), "email": admin.Email},
	})
}

// ImpersonateStop restores the original admin identity on the session. It is
// reachable by any authenticated session (an impersonating session has the
// target's reduced privileges), but only does anything when impersonation is active.
func (a *Auth) ImpersonateStop(w http.ResponseWriter, r *http.Request) {
	sessID := sessionIDFrom(r.Context())
	sess, ok := SessionFrom(r.Context())
	if !ok || sessID == "" || sess.ImpersonatorID == nil {
		web.Error(w, http.StatusBadRequest, "not_impersonating", "no active impersonation")
		return
	}
	target := MustUser(r.Context())
	adminID := *sess.ImpersonatorID

	next := *sess
	next.UserID = adminID
	next.ImpersonatorID = nil
	next.ImpersonatorEmail = ""
	if err := a.saveSession(r.Context(), sessID, next); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update session")
		return
	}
	admin, err := a.Store.GetUserByID(r.Context(), adminID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not restore admin")
		return
	}
	_ = a.Store.Audit(r.Context(), &target.AccountID, &adminID, "admin.impersonate_stop", target.Email, clientIP(r), nil)
	web.JSON(w, http.StatusOK, map[string]any{"user": toUserDTO(admin)})
}
