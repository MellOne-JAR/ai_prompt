/**
 * Security Rules Invariant Verification Spec (Dirty Dozen Test Matrix)
 * Mirrors the exact boolean gates enforced in firestore.rules for /prompts/{promptId}.
 */

interface MockAuth {
  uid: string;
  token: {
    email: string;
    email_verified: boolean;
  };
}

interface PromptPayload {
  title?: unknown;
  category?: unknown;
  content?: unknown;
  createdAt?: unknown;
  [extraKey: string]: unknown;
}

const ADMIN_EMAIL = 'onsu0619@gmail.com';
const VALID_CATEGORIES = new Set(['사진 합성', '스타일 변환', '캐릭터·포스터']);

function isValidId(id: string): boolean {
  return typeof id === 'string' && id.length <= 128 && /^[a-zA-Z0-9_-]+$/.test(id);
}

function isAdmin(auth: MockAuth | null): boolean {
  return (
    auth !== null &&
    auth.token.email_verified === true &&
    auth.token.email === ADMIN_EMAIL
  );
}

function isValidPrompt(data: PromptPayload): boolean {
  const keys = Object.keys(data);
  const required = ['title', 'category', 'content', 'createdAt'];
  const hasAll = required.every((k) => keys.includes(k));
  const hasOnly = keys.every((k) => required.includes(k));
  return (
    hasAll &&
    hasOnly &&
    typeof data.title === 'string' &&
    data.title.length >= 1 &&
    data.title.length <= 100 &&
    typeof data.category === 'string' &&
    VALID_CATEGORIES.has(data.category) &&
    typeof data.content === 'string' &&
    data.content.length >= 1 &&
    data.content.length <= 10000 &&
    typeof data.createdAt === 'number'
  );
}

function canCreate(
  auth: MockAuth | null,
  promptId: string,
  incoming: PromptPayload,
  requestTime: number
): boolean {
  return (
    isAdmin(auth) &&
    isValidId(promptId) &&
    isValidPrompt(incoming) &&
    incoming.createdAt === requestTime
  );
}

function canUpdate(
  auth: MockAuth | null,
  promptId: string,
  incoming: PromptPayload,
  existing: PromptPayload
): boolean {
  const affectedKeys = new Set(
    [...Object.keys(incoming), ...Object.keys(existing)].filter(
      (k) => incoming[k] !== existing[k]
    )
  );
  const allowedUpdateKeys = new Set(['title', 'category', 'content']);
  const onlyAllowedAffected = [...affectedKeys].every((k) => allowedUpdateKeys.has(k));

  return (
    isAdmin(auth) &&
    isValidId(promptId) &&
    isValidPrompt(incoming) &&
    incoming.createdAt === existing.createdAt &&
    onlyAllowedAffected
  );
}

function canDelete(auth: MockAuth | null, promptId: string): boolean {
  return isAdmin(auth) && isValidId(promptId);
}

export function runDirtyDozenChecks(): { passed: number; total: number } {
  const now = 1700000000000;
  const adminAuth: MockAuth = {
    uid: 'admin-uid',
    token: { email: ADMIN_EMAIL, email_verified: true }
  };
  const validExisting: PromptPayload = {
    title: '테스트',
    category: '사진 합성',
    content: '내용',
    createdAt: now
  };

  const results: boolean[] = [
    // 1. Unauthenticated Create
    !canCreate(null, 'p1', validExisting, now),
    // 2. Non-Admin User Create
    !canCreate({ uid: 'u2', token: { email: 'guest@example.com', email_verified: true } }, 'p1', validExisting, now),
    // 3. Spoofed Unverified Admin Email
    !canCreate({ uid: 'u3', token: { email: ADMIN_EMAIL, email_verified: false } }, 'p1', validExisting, now),
    // 4. Shadow Field on Create
    !canCreate(adminAuth, 'p1', { ...validExisting, isFeatured: true }, now),
    // 5. Missing Required Field
    !canCreate(adminAuth, 'p1', { title: '제목', category: '사진 합성', createdAt: now }, now),
    // 6. Invalid Category
    !canCreate(adminAuth, 'p1', { ...validExisting, category: '기타' }, now),
    // 7. Oversized Title (> 100)
    !canCreate(adminAuth, 'p1', { ...validExisting, title: 'a'.repeat(101) }, now),
    // 8. Oversized Content (> 10,000)
    !canCreate(adminAuth, 'p1', { ...validExisting, content: 'a'.repeat(10001) }, now),
    // 9. Spoofed Client Timestamp on Create
    !canCreate(adminAuth, 'p1', { ...validExisting, createdAt: now - 5000 }, now),
    // 10. Immutable createdAt Tampering on Update
    !canUpdate(adminAuth, 'p1', { ...validExisting, createdAt: now + 1000 }, validExisting),
    // 11. Non-Admin Delete
    !canDelete({ uid: 'u2', token: { email: 'guest@example.com', email_verified: true } }, 'p1'),
    // 12. Path Variable ID Poisoning
    !canCreate(adminAuth, 'bad$id..!', validExisting, now)
  ];

  const passed = results.filter(Boolean).length;
  return { passed, total: results.length };
}
