# Firestore Security Specification

## 1. Data Invariants
- All documents reside in `/prompts/{promptId}` and contain strictly `title`, `category`, `content`, and `createdAt`.
- `prompts` is a public non-PII catalog: guests (unauthenticated) and authenticated users may `get` and `list` documents.
- Only the single verified administrator (`request.auth.token.email == 'onsu0619@gmail.com'` AND `request.auth.token.email_verified == true`) may `create`, `update`, or `delete` documents in `/prompts/{promptId}`.
- `createdAt` must equal `request.time` on `create` and must remain immutable (`incoming().createdAt == existing().createdAt`) on `update`.
- `category` must be one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
- `title` must be a non-empty string up to 100 characters; `content` must be a non-empty string up to 10,000 characters.
- Document IDs (`promptId`) must match `^[a-zA-Z0-9_\-]+$` and be at most 128 characters.

## 2. The "Dirty Dozen" Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated Create**: Guest (`auth == null`) attempts to create a prompt in `/prompts/p1`.
2. **Non-Admin User Create**: Signed-in user with `email: "user@example.com"`, `email_verified: true` attempts to create a prompt.
3. **Spoofed Unverified Admin Email**: Signed-in user with `email: "onsu0619@gmail.com"`, `email_verified: false` attempts to create/update/delete a prompt.
4. **Shadow / Ghost Field on Create**: Admin attempts to create a prompt with an extra field `{ isFeatured: true }`.
5. **Missing Required Field**: Admin attempts to create a prompt without `content`.
6. **Invalid Category Value**: Admin attempts to create a prompt with `category: "기타"`.
7. **Oversized Title Poisoning**: Admin attempts to create a prompt with a 101-character `title`.
8. **Oversized Content Poisoning**: Admin attempts to create a prompt with a 10,001-character `content`.
9. **Spoofed Client Timestamp on Create**: Admin attempts to create a prompt with a backdated `createdAt` not equal to `request.time`.
10. **Immutable `createdAt` Tampering on Update**: Admin attempts to modify `createdAt` during an update.
11. **Non-Admin Update/Delete**: Non-admin authenticated user attempts to update or delete an existing prompt.
12. **Path Variable ID Poisoning**: Admin attempts to create/update/delete `/prompts/bad$id..!` with invalid characters.
