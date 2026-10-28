const SAFE_ID = /^[0-9a-zA-Z_-]{1,64}$/;

// Only identifiers from the route are recorded as the target; bodies, query strings and
// anything else the caller controls are left out so the audit trail carries no private content.
const pickTarget = (pathParameters) => {
  const target = {};
  for (const [key, value] of Object.entries(pathParameters || {})) {
    if (typeof value === "string" && SAFE_ID.test(value)) target[key] = value;
  }
  return target;
};

const READ_ONLY_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Writes one structured audit record for a request. Recorded for every state-changing
 * request, every request to a privileged (admin) surface, and every denied request.
 */
const auditLog = (event, response, { privileged = false } = {}) => {
  const status = response.statusCode;
  const denied = status === 401 || status === 403;
  const changesState = !READ_ONLY_METHODS.has(event.httpMethod);

  if (!privileged && !denied && !changesState) return;

  const authorizer = event.requestContext?.authorizer || {};
  console.log(
    JSON.stringify({
      audit: true,
      timestamp: new Date().toISOString(),
      requestId: event.requestContext?.requestId,
      actor: authorizer.userId || authorizer.principalId || "anonymous",
      actorRole: authorizer.role || "user",
      sourceIp: event.requestContext?.identity?.sourceIp,
      action: `${event.httpMethod} ${event.resource}`,
      target: pickTarget(event.pathParameters),
      outcome: denied ? "denied" : status >= 400 ? "failed" : "success",
      statusCode: status,
    })
  );
};

module.exports = { auditLog };
