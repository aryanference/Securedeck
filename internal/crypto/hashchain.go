package crypto

import (
	"crypto/sha256"
)

// ComputeEntryHash uses sha256(prevHash || entryContent)
func ComputeEntryHash(prevHash []byte, entryContent []byte) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(entryContent)
	return h.Sum(nil)
}

type AuditEntry struct {
	EntryHash []byte
	PrevHash  []byte
	Content   []byte // canonical bytes representation of the event
}

func VerifyChain(entries []AuditEntry) (bool, int) {
	for i, entry := range entries {
		expectedHash := ComputeEntryHash(entry.PrevHash, entry.Content)
		
		if string(expectedHash) != string(entry.EntryHash) {
			return false, i
		}
		
		if i > 0 {
			if string(entry.PrevHash) != string(entries[i-1].EntryHash) {
				return false, i
			}
		}
	}
	return true, -1
}
