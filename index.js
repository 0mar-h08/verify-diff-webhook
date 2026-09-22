import 'dotenv/config';
import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import { App } from '@octokit/app';
import { Octokit } from '@octokit/rest';

const {
  GITHUB_APP_ID,
  GITHUB_PRIVATE_KEY_PATH,
  GITHUB_WEBHOOK_SECRET,
  PORT = 3000,
} = process.env;

if (!GITHUB_APP_ID || !GITHUB_PRIVATE_KEY_PATH || !GITHUB_WEBHOOK_SECRET) {
  console.warn(
    'Warning: Missing one or more required environment variables (GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH, GITHUB_WEBHOOK_SECRET).'
  );
}

const app = express();

/**
 * Verify GitHub webhook HMAC SHA-256 signature against raw body buffer.
 */
function verifySignature(secret, signatureHeader, rawBody) {
  if (!secret || !signatureHeader || !signatureHeader.startsWith('sha256=')) {
    return false;
  }

  if (!rawBody || !Buffer.isBuffer(rawBody)) {
    return false;
  }

  const signatureHex = signatureHeader.slice(7).trim();
  const expectedHex = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  const signatureBuffer = Buffer.from(signatureHex, 'hex');
  const expectedBuffer = Buffer.from(expectedHex, 'hex');

  if (signatureBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(signatureBuffer, expectedBuffer);
}

/**
 * Helper to get GitHub App instance
 */
function getGitHubApp() {
  const privateKey = fs.readFileSync(GITHUB_PRIVATE_KEY_PATH, 'utf8');
  return new App({
    appId: GITHUB_APP_ID,
    privateKey,
    Octokit,
  });
}

/**
 * Handle push event payload and fetch commit diffs
 */
async function handlePushEvent(payload) {
  const repoFullName = payload.repository?.full_name;
  const installationId = payload.installation?.id;

  if (!repoFullName) {
    console.error('Missing repository.full_name in push payload.');
    return;
  }

  if (!installationId) {
    console.error('Missing installation.id in payload.');
    return;
  }

  const commitShas = (payload.commits || [])
    .map((c) => c.id)
    .filter(Boolean);

  if (commitShas.length === 0 && payload.head_commit?.id) {
    commitShas.push(payload.head_commit.id);
  }

  if (commitShas.length === 0) {
    console.log(`No commits found in push event for ${repoFullName}.`);
    return;
  }

  const [owner, repo] = repoFullName.split('/');

  try {
    const gitHubApp = getGitHubApp();
    const octokit = await gitHubApp.getInstallationOctokit(installationId);

    for (const sha of commitShas) {
      const { data: commitData } = await octokit.rest.repos.getCommit({
        owner,
        repo,
        ref: sha,
      });

      const commitMessage = commitData.commit?.message;
      const diffPatches = (commitData.files || [])
        .map((file) => `File: ${file.filename}\n${file.patch || '(No patch content - binary or unchanged)'}`)
        .join('\n\n--- \n\n');

      console.log('========================================');
      console.log(`Repository: ${repoFullName}`);
      console.log(`Commit SHA: ${sha}`);
      console.log(`Commit Message:\n${commitMessage}`);
      console.log(`Diff / Patch:\n${diffPatches || '(No file changes)'}`);
      console.log('========================================\n');
    }
  } catch (error) {
    console.error(`Error processing commits for ${repoFullName}:`, error);
  }
}

// POST endpoint for GitHub webhook
// express.raw({ type: 'application/json' }) is scoped specifically to this route
// and runs before any JSON parsing to preserve the exact raw buffer for HMAC verification.
app.post(
  '/webhook/github',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const rawBody = req.body;
    const signatureHeader = req.get('x-hub-signature-256') || req.headers['x-hub-signature-256'];
    const event = req.get('x-github-event') || req.headers['x-github-event'];

    // Verify signature
    const isValid = verifySignature(GITHUB_WEBHOOK_SECRET, signatureHeader, rawBody);
    if (!isValid) {
      console.warn('Invalid or missing webhook signature. Rejecting with 401.');
      return res.status(401).send('Unauthorized: Invalid signature');
    }

    // Immediately respond with 200 OK after signature verification
    res.status(200).send('Webhook received');

    // Parse JSON body after verification
    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch (parseErr) {
      console.error('Failed to parse JSON body:', parseErr);
      return;
    }

    if (event === 'push') {
      handlePushEvent(payload).catch((err) => {
        console.error('Unhandled error in handlePushEvent:', err);
      });
    } else {
      console.log(`Received GitHub event "${event}", ignoring.`);
    }
  }
);

app.listen(PORT, () => {
  console.log(`GitHub webhook server is listening on port ${PORT}`);
});
