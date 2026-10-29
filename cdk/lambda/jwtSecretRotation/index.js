const {
  SecretsManagerClient,
  DescribeSecretCommand,
  GetSecretValueCommand,
  GetRandomPasswordCommand,
  PutSecretValueCommand,
  UpdateSecretVersionStageCommand,
} = require("@aws-sdk/client-secrets-manager");

const secretsManager = new SecretsManagerClient();

// Same shape and character set as the secret generated at deploy time
const PASSWORD_LENGTH = 128;
const EXCLUDED_CHARACTERS = String.raw`"@/\'`;

// Secrets Manager rotation handler for the token signing secret. Nothing external holds a
// copy of the key, so there is no setSecret/testSecret work: a new version is generated,
// then promoted. The previous version keeps the AWSPREVIOUS stage, which the verifiers
// honour only for a short window after the rotation.
exports.handler = async ({ SecretId, ClientRequestToken, Step }) => {
  const metadata = await secretsManager.send(new DescribeSecretCommand({ SecretId }));
  if (!metadata.RotationEnabled) {
    throw new Error(`Rotation is not enabled for secret ${SecretId}`);
  }

  const stages = metadata.VersionIdsToStages?.[ClientRequestToken];
  if (!stages) {
    throw new Error(`Version ${ClientRequestToken} has no staging labels for secret ${SecretId}`);
  }
  if (stages.includes("AWSCURRENT")) return; // already promoted
  if (!stages.includes("AWSPENDING")) {
    throw new Error(`Version ${ClientRequestToken} is not staged AWSPENDING for secret ${SecretId}`);
  }

  switch (Step) {
    case "createSecret": {
      try {
        await secretsManager.send(
          new GetSecretValueCommand({
            SecretId,
            VersionId: ClientRequestToken,
            VersionStage: "AWSPENDING",
          })
        );
        return; // already created by an earlier attempt
      } catch (error) {
        if (error.name !== "ResourceNotFoundException") throw error;
      }

      const { RandomPassword } = await secretsManager.send(
        new GetRandomPasswordCommand({
          PasswordLength: PASSWORD_LENGTH,
          ExcludeCharacters: EXCLUDED_CHARACTERS,
        })
      );
      await secretsManager.send(
        new PutSecretValueCommand({
          SecretId,
          ClientRequestToken,
          SecretString: JSON.stringify({ jwtSecret: RandomPassword }),
          VersionStages: ["AWSPENDING"],
        })
      );
      return;
    }

    case "setSecret":
    case "testSecret":
      return;

    case "finishSecret": {
      const currentVersion = Object.entries(metadata.VersionIdsToStages).find(([, labels]) =>
        labels.includes("AWSCURRENT")
      )?.[0];
      if (currentVersion === ClientRequestToken) return;

      await secretsManager.send(
        new UpdateSecretVersionStageCommand({
          SecretId,
          VersionStage: "AWSCURRENT",
          MoveToVersionId: ClientRequestToken,
          RemoveFromVersionId: currentVersion,
        })
      );
      return;
    }

    default:
      throw new Error(`Unknown rotation step: ${Step}`);
  }
};
