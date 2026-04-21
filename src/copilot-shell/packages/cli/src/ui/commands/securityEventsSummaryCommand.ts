/**
 * /security-events-summary magic command
 *
 * Delegates to `agent-sec-cli events --summary` and displays the result.
 * All aggregation and formatting is handled by the Python CLI;
 * this command is a thin pipe-through.
 */

import { execFile } from 'node:child_process';
import type {
  SlashCommand,
  CommandContext,
  MessageActionReturn,
} from './types.js';
import { CommandKind } from './types.js';
import { t } from '../../i18n/index.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Timeout for agent-sec-cli execution in milliseconds. */
const EXEC_TIMEOUT_MS = 15_000;

/** Max stdout buffer size (5 MB). */
const MAX_BUFFER = 5 * 1024 * 1024;

/**
 * Flags that conflict with --summary or override the time window we control.
 * Anything not in ALLOWED_FLAGS is silently dropped.
 */
const ALLOWED_FLAGS = new Set(['--event-type', '--category']);

/**
 * Patterns that indicate stderr is an internal traceback rather than a
 * user-facing error message. When matched, we fall back to a generic
 * error instead of forwarding stderr to the user.
 */
const TRACEBACK_PATTERN = /Traceback \(most recent call last\)|\.py:\d+/;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Async wrapper around execFile('agent-sec-cli', ...).
 * Fail-open: never rejects. Returns CliResult for all outcomes.
 */
function runAgentSecCli(args: string[]): Promise<CliResult> {
  return new Promise((resolve) => {
    execFile(
      'agent-sec-cli',
      args,
      { timeout: EXEC_TIMEOUT_MS, maxBuffer: MAX_BUFFER },
      (error, stdout, stderr) => {
        if (error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
          resolve({ stdout: '', stderr: '', exitCode: -1 });
          return;
        }
        if (error && error.killed) {
          resolve({ stdout: '', stderr: '', exitCode: 124 });
          return;
        }
        // ENOBUFS: output exceeded maxBuffer
        if (
          error &&
          (error as NodeJS.ErrnoException).code ===
            'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
        ) {
          resolve({ stdout: '', stderr: '', exitCode: -2 });
          return;
        }
        const exitCode =
          typeof (error as { code?: number })?.code === 'number'
            ? (error as { code: number }).code
            : error
              ? 1
              : 0;
        resolve({
          stdout: (stdout ?? '').trim(),
          stderr: (stderr ?? '').trim(),
          exitCode,
        });
      },
    );
  });
}

/**
 * Parse command arguments for /security-events-summary.
 * Extracts --last-hours N (default 24, capped at 720).
 */
function parseArgs(args: string): {
  lastHours: number;
  extraArgs: string[];
  error?: string;
} {
  const parts = args.trim().split(/\s+/).filter(Boolean);
  let lastHours = 24;
  const extraArgs: string[] = [];

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '--last-hours' && i + 1 < parts.length) {
      const val = Number(parts[i + 1]);
      if (isNaN(val)) {
        return {
          lastHours: 24,
          extraArgs: [],
          error: t('Invalid --last-hours value. Must be a positive number.'),
        };
      }
      lastHours = val <= 0 ? 24 : val > 720 ? 720 : val;
      i++; // skip the value
    } else if (ALLOWED_FLAGS.has(parts[i]!) && i + 1 < parts.length) {
      // Whitelisted flag — pass value through without validation;
      // the CLI owns enum validation and emits its own warnings.
      extraArgs.push(parts[i]!, parts[i + 1]!);
      i++; // skip the value
    }
    // All other flags are silently dropped to prevent injection
  }

  return { lastHours, extraArgs };
}

// ---------------------------------------------------------------------------
// Command Definition
// ---------------------------------------------------------------------------

export const securityEventsSummaryCommand: SlashCommand = {
  name: 'security-events-summary',
  get description() {
    return t('Show security posture summary from agent-sec-cli events');
  },
  kind: CommandKind.BUILT_IN,
  action: async (
    _context: CommandContext,
    args: string,
  ): Promise<MessageActionReturn> => {
    // Parse arguments
    const { lastHours, extraArgs, error: parseError } = parseArgs(args);
    if (parseError) {
      return { type: 'message', messageType: 'error', content: parseError };
    }

    // Build CLI args — delegate formatting to agent-sec-cli
    const cliArgs = [
      'events',
      '--summary',
      '--last-hours',
      String(lastHours),
      ...extraArgs,
    ];

    // Execute agent-sec-cli
    const result = await runAgentSecCli(cliArgs);

    // Handle errors
    if (result.exitCode === -1) {
      return {
        type: 'message',
        messageType: 'error',
        content: t(
          'agent-sec-cli not found on PATH. Install agent-sec-core first.',
        ),
      };
    }
    if (result.exitCode === 124) {
      return {
        type: 'message',
        messageType: 'error',
        content: t('agent-sec-cli timed out after {{seconds}} seconds.', {
          seconds: String(EXEC_TIMEOUT_MS / 1000),
        }),
      };
    }
    if (result.exitCode === -2) {
      return {
        type: 'message',
        messageType: 'error',
        content: t(
          'agent-sec-cli output exceeded the maximum buffer size. Try a shorter --last-hours window.',
        ),
      };
    }
    if (result.exitCode !== 0) {
      // Prefer the CLI's own error message when it looks user-facing.
      // Fall back to generic text when stderr is empty or contains a
      // Python traceback (which may leak internal file paths).
      const cliError =
        result.stderr && !TRACEBACK_PATTERN.test(result.stderr)
          ? result.stderr
          : t(
              'agent-sec-cli exited with code {{code}}. Ensure agent-sec-core is properly installed and the SQLite store is accessible.',
              { code: String(result.exitCode) },
            );
      return { type: 'message', messageType: 'error', content: cliError };
    }

    // Surface CLI warnings (e.g. "Unknown category 'aaa'") from stderr.
    // When the CLI succeeds but emits a non-traceback warning, prepend it
    // so the user sees it alongside (or instead of) the summary output.
    const cliWarning =
      result.stderr && !TRACEBACK_PATTERN.test(result.stderr)
        ? result.stderr
        : '';

    // Empty stdout: CLI succeeded but no events to summarize
    if (!result.stdout) {
      return {
        type: 'message',
        messageType: cliWarning ? 'error' : 'info',
        content:
          cliWarning ||
          t('No security events in the last {{hours}} hours.', {
            hours: String(lastHours),
          }),
      };
    }

    // Pass through the summary output from agent-sec-cli
    const content = cliWarning
      ? `${cliWarning}\n\n${result.stdout}`
      : result.stdout;
    return { type: 'message', messageType: 'info', content };
  },
};
