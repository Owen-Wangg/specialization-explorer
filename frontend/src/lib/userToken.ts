export const USER_STORAGE_KEY = "specEx_user_session";

/**
 * Fetches a JWT from /user/publicToken. When the stored user has a key the
 * token is bound to that user, which the chat endpoints require.
 */
export async function fetchUserToken(): Promise<string> {
  const headers: Record<string, string> = {};

  try {
    const raw = localStorage.getItem(USER_STORAGE_KEY);
    const stored = raw ? (JSON.parse(raw) as { userId?: string; userKey?: string }) : null;
    if (stored?.userId && stored?.userKey) {
      headers.Authorization = `UserKey ${stored.userId}:${stored.userKey}`;
    }
  } catch {
    // Fall through to an anonymous token
  }

  const response = await fetch(
    `${import.meta.env.VITE_API_ENDPOINT}/user/publicToken`,
    { headers }
  );
  if (!response.ok) {
    throw new Error(`Token request failed with status ${response.status}`);
  }

  const { token } = await response.json();
  return token;
}
