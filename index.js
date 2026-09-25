import 'dotenv/config';
import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import { App } from '@octokit/app';
import { Octokit } from '@octokit/rest';
import OpenAI from 'openai';

const openai = new OpenAI({
  baseURL: 'https://api.groq.com/openai/v1',
  apiKey: process.env.GROQ_API_KEY,
});

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

      let reviewText;
      try {
        const completion = await openai.chat.completions.create({
          model: 'openai/gpt-oss-120b',
          messages: [
            {
              role: 'system',
              content:
                "You are a skeptical senior engineer reviewing another AI's work. You didn't write this code and have no reason to be diplomatic about it. You will be given a TASK and CHANGES (a code diff). Determine whether CHANGES actually accomplishes TASK. Don't assume good faith — assume the work may be incomplete, superficial, or unrelated, and prove otherwise from the evidence in front of you. For each distinct thing the task asked for, output one line: ✅ CONFIRMED — [what was asked] — [one plain sentence citing exactly what in the code proves this, no jargon], OR ⚠️ CAN'T CONFIRM — [what was asked] — [one sentence on what's missing or unclear], OR ❌ CONTRADICTED — [what was asked] — [one sentence on what the code does instead]. Rules: never mark CONFIRMED unless you can point to the specific part of the code doing it; if the change only touches surface-level things while the actual logic needed is untouched, that's CAN'T CONFIRM or CONTRADICTED, not CONFIRMED; do not comment on code quality, security, or architecture — out of scope; write for someone who cannot read code, no jargon. Before finalizing your answer, check that each line's label matches its own stated reasoning — if your explanation says something was done or is present, the label must be CONFIRMED, not CONTRADICTED; if your explanation says something is missing or wrong, the label must be CONTRADICTED, not CONFIRMED.",
            },
            {
              role: 'user',
              content: `TASK:\n${commitMessage}\n\nCHANGES:\n${diffPatches}`,
            },
          ],
        });

        reviewText = completion.choices[0]?.message?.content || '';
      } catch (error) {
        console.error('Error calling Groq API:', error);
        reviewText = `Review unavailable: ${error.message}`;
      }

      console.log('========================================');
      console.log(`Repository: ${repoFullName}`);
      console.log(`Commit SHA: ${sha}`);
      console.log(`Commit Message:\n${commitMessage}`);
      console.log(`Diff / Patch:\n${diffPatches || '(No file changes)'}`);
      console.log(`Review:\n${reviewText}`);
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
