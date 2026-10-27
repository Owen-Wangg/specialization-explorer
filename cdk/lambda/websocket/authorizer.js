const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");
const jwt = require("jsonwebtoken");

const secretsManager = new SecretsManagerClient();
let cachedSecret;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// $connect authorizer: only tokens bound to a user (sub is a user UUID) are accepted.
// The verified user id is exposed to every later route on this connection via
// requestContext.authorizer.userId.
exports.handler = async (event) => {
  const token = event.queryStringParameters?.token;

  if (!token) {
    console.warn("WebSocket connect rejected: missing token");
    throw new Error("Unauthorized");
  }

  try {
    if (!cachedSecret) {
      const response = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: process.env.JWT_SECRET })
      );
      cachedSecret = JSON.parse(response.SecretString).jwtSecret;
    }

    const decoded = jwt.verify(token, cachedSecret, {
      algorithms: ["HS256"],
      issuer: "specex-public-token",
      audience: "specex-api",
    });

    if (typeof decoded?.sub !== "string" || !UUID_REGEX.test(decoded.sub)) {
      console.warn("WebSocket connect rejected: token is not bound to a user");
      throw new Error("Unauthorized");
    }

    return {
      principalId: decoded.sub,
      policyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Action: "execute-api:Invoke",
            Effect: "Allow",
            Resource: event.methodArn,
          },
        ],
      },
      context: { userId: decoded.sub },
    };
  } catch (error) {
    console.error("WebSocket connect rejected: invalid token", error?.message);
    throw new Error("Unauthorized");
  }
};
