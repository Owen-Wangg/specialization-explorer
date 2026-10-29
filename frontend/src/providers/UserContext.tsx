import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { UserContext } from "./user";
import { fetchUserToken, USER_STORAGE_KEY } from "@/lib/userToken";

// A stored key older than this is replaced, which limits how long a leaked key stays usable
const KEY_ROTATION_INTERVAL_MS = 24 * 60 * 60 * 1000;

export function UserProvider({ children }: { children: ReactNode }) {
  const [userId, setUserId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const LOCAL_KEY = USER_STORAGE_KEY;

  useEffect(() => {
    const validateUser = async (stored: {
      userId: string;
      userKey: string;
      createdAt?: string;
      keyIssuedAt?: string;
    }) => {
      try {
        // token bound to the stored user
        const token = await fetchUserToken();

        // Validate user exists
        const validateResp = await fetch(
          `${import.meta.env.VITE_API_ENDPOINT}/user/${stored.userId}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!validateResp.ok) return false;

        const issuedAt = Date.parse(stored.keyIssuedAt ?? "");
        if (Number.isNaN(issuedAt) || Date.now() - issuedAt > KEY_ROTATION_INTERVAL_MS) {
          await rotateKey(stored, token);
        }
        return true;
      } catch (e) {
        console.error("Error validating user:", e);
        return false;
      }
    };

    // Failure keeps the current key, which stays valid until a rotation succeeds
    const rotateKey = async (
      stored: { userId: string; userKey: string; createdAt?: string },
      token: string
    ) => {
      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_ENDPOINT}/user/${stored.userId}/key`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ currentKey: stored.userKey }),
          }
        );
        if (!response.ok) return;

        const { userKey } = await response.json();
        if (!userKey) return;

        localStorage.setItem(
          LOCAL_KEY,
          JSON.stringify({
            userId: stored.userId,
            userKey,
            createdAt: stored.createdAt,
            keyIssuedAt: new Date().toISOString(),
          })
        );
      } catch (e) {
        console.warn("Failed to rotate user key:", e);
      }
    };

    const createUser = async () => {
      try {
        // First get a public token
        const tokenResponse = await fetch(
          `${import.meta.env.VITE_API_ENDPOINT}/user/publicToken`
        );
        if (!tokenResponse.ok) throw new Error("Failed to get public token");
        const { token } = await tokenResponse.json();

        // Create user
        const response = await fetch(`${import.meta.env.VITE_API_ENDPOINT}/user`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ role: "student" }), // Default to student on creation
        });

        if (!response.ok) {
          throw new Error("Failed to create user");
        }

        const data = await response.json();

        const id = data.userId
        if (!id || !data.userKey) {
          throw new Error("Create user response missing user credentials");
        }

        const payload = {
          userId: id,
          userKey: data.userKey,
          createdAt: new Date().toISOString(),
          keyIssuedAt: new Date().toISOString(),
        };

        try {
          localStorage.setItem(LOCAL_KEY, JSON.stringify(payload));
        } catch {
          console.warn("Failed to store user in localStorage");
        }

        setUserId(payload.userId);
      } catch (err) {
        setError(err instanceof Error ? err : new Error("Failed to create user"));
      } finally {
        setIsLoading(false);
      }
    };

    const bootstrap = async () => {
      try {
        const raw = localStorage.getItem(LOCAL_KEY);
        if (raw) {
          try {
            const parsed = JSON.parse(raw) as {
              userId: string;
              userKey?: string;
              createdAt?: string;
              keyIssuedAt?: string;
            };

            // Sessions stored before user keys existed cannot get a user-bound token
            if (parsed.userId && parsed.userKey) {
              const ok = await validateUser({ ...parsed, userKey: parsed.userKey });
              if (ok) {
                setUserId(parsed.userId);
                setIsLoading(false);
                return;
              }
            }
          } catch (e) {
            console.error("Error parsing stored user:", e);
            // parsing error — treat as missing
          }
        }

        // create a new user only if none valid
        await createUser();
      } catch (e) {
        setError(e instanceof Error ? e : new Error("Failed to initialize user"));
        setIsLoading(false);
      }
    };

    bootstrap();
  }, []); // Only run once when the app starts

  return (
    <UserContext.Provider value={{ userId, isLoading, error }}>
      {children}
    </UserContext.Provider>
  );
}
