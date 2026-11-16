package api

// Wallet notifications use the platform's generic app message. Its banner
// text is fixed by kind, so nothing Drive writes reaches Apple or Google in
// the clear; the wallet opens the path on Drive's own host, which the
// platform supplies, never Drive. Nothing else rides in the payload: the
// wallet shows no file names, only who is asking, with its own labels.
const appMessage = "app-message"

// requestMessage tells a sharer that someone asks to open their link. The
// path lands on the Requests view of the drive the link belongs to.
// presented carries what the requester presented, keyed by attribute name;
// the wallet keeps only the names it knows and labels them itself.
func requestMessage(tenantID string, presented map[string]string) map[string]any {
	m := map[string]any{"kind": "request", "path": "/#requests/" + tenantID}
	if len(presented) > 0 {
		m["presented"] = presented
	}
	return m
}

// responseMessage tells a requester that the sharer decided. Whatever the
// decision, the place to look is Shared with me.
func responseMessage() map[string]any {
	return map[string]any{"kind": "response", "path": "/#shared"}
}
