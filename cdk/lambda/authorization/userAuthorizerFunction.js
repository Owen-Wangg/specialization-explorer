const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");
const jwt = require("jsonwebtoken");

const secretsManager = new SecretsManagerClient();
let cachedSecret;
let cacheExpiry = 0;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const ANONYMOUS_RESOURCES = [
  "POST/user",
  "GET/system_message/*",
  "GET/system-settings/*",
];

exports.handler = async (event) => {
  const token = event.authorizationToken?.replace("Bearer ", "");

  if (!token) {
    console.warn("No token provided");
    throw new Error("Unauthorized");
  }

  try {
    if (!cachedSecret || Date.now() > cacheExpiry) {
      const response = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: process.env.JWT_SECRET })
      );
      cachedSecret = JSON.parse(response.SecretString).jwtSecret;
      cacheExpiry = Date.now() + CACHE_TTL_MS;
    }

    const decoded = jwt.verify(token, cachedSecret);

    // methodArn format: arn:aws:execute-api:region:account:apiId/stage/method/resource
    const arnParts = event.methodArn.split('/');
    const apiGatewayArnPrefix = arnParts.slice(0, 2).join('/'); // arn:aws:execute-api:region:account:apiId/stage

    // Tokens bound to a user (sub) may call the user-tier API. Anonymous tokens
    // can only create a user and read the shared public settings.
    const resources = decoded.sub
      ? [`${apiGatewayArnPrefix}/*/*`]
      : ANONYMOUS_RESOURCES.map((r) => `${apiGatewayArnPrefix}/${r}`);

    const policy = generatePolicy(decoded.sub || "anonymous", "Allow", resources);
    policy.context = {
      ...decoded,
      ...(decoded.sub && { userId: decoded.sub }),
    };
    return policy;
  } catch (err) {
    console.error("Authorization error:", err.message);
    throw new Error("Unauthorized");
  }
};

function generatePolicy(principalId, effect, resources) {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resources,
        },
      ],
    },
  };
}