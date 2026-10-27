const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");
const jwt = require("jsonwebtoken");
const { getCorsHeaders } = require("./cors.js");
const crypto = require("crypto");
const { randomUUID } = crypto;

// Must match the verification options in the user and WebSocket authorizers
const TOKEN_OPTIONS = { algorithm: "HS256", issuer: "specex-public-token", audience: "specex-api" };

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const secretsManager = new SecretsManagerClient();
let cachedSecret;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

exports.handler = async (event) => {
  try {
    if (!cachedSecret || Date.now() > cacheExpiry) {
      const response = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: process.env.JWT_SECRET })
      );
      cachedSecret = JSON.parse(response.SecretString).jwtSecret;
      cacheExpiry = Date.now() + CACHE_TTL_MS;
    }

    // Optional "Authorization: UserKey <userId>:<userKey>" binds the token to a user.
    // Without it the token is anonymous (no sub) and cannot act as any user.
    let subject;
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    if (authHeader?.startsWith("UserKey ")) {
      const [userId, userKey] = authHeader.slice("UserKey ".length).trim().split(":");
      const expected = crypto
        .createHmac("sha256", cachedSecret)
        .update(`user-key:${userId}`)
        .digest("hex");
      const provided = Buffer.from(userKey || "");
      const expectedBuf = Buffer.from(expected);
      if (
        !UUID_REGEX.test(userId || "") ||
        provided.length !== expectedBuf.length ||
        !crypto.timingSafeEqual(provided, expectedBuf)
      ) {
        return {
          statusCode: 401,
          headers: await getCorsHeaders(event),
          body: JSON.stringify({ error: "Invalid user credentials" }),
        };
      }
      subject = userId;
    }

    const token = jwt.sign(
      {
        ...(subject && { sub: subject }),
        role: "user",
        jti: randomUUID(),  // Unique token ID for tracking/revocation
        iat: Math.floor(Date.now() / 1000)  // Explicit issued-at timestamp
      },
      cachedSecret,
      { expiresIn: "15m", ...TOKEN_OPTIONS }  // Reduced to 15 minutes for better security
    );
    return {
      statusCode: 200,
      headers: await getCorsHeaders(event),
      body: JSON.stringify({ token }),
    };
  } catch (error) {
    console.error("Token generation error:", error);
    return {
      statusCode: 500,
      headers: await getCorsHeaders(event),
      body: JSON.stringify({ error: "Failed to generate token" }),
    };
  }
};
