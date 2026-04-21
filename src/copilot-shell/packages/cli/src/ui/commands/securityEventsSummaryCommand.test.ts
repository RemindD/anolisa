/**
 * Unit tests for /security-events-summary command.
 *
 * The command is a thin pipe-through to `agent-sec-cli events --summary`.
 * Tests verify argument parsing, error handling, and stdout forwarding.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { securityEventsSummaryCommand } from './securityEventsSummaryCommand.js';
import { CommandKind, type CommandContext } from './types.js';
import { createMockCommandContext } from '../../test-utils/mockCommandContext.js';

// Mock i18n - return key as-is for test assertions
vi.mock('../../i18n/index.js', () => ({
  t: vi.fn((key: string, params?: Record<string, string>) => {
    if (!params) return key;
    let result = key;
    for (const [k, v] of Object.entries(params)) {
      result = result.replace(`{{${k}}}`, v);
    }
    return result;
  }),
}));

// Mock node:child_process
const { mockExecFile } = vi.hoisted(() => ({
  mockExecFile: vi.fn(),
}));
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    execFile: mockExecFile,
    default: {
      ...(actual as unknown as Record<string, unknown>),
      execFile: mockExecFile,
    },
  };
});

// Helper: simulate execFile callback
function mockExecFileResult(opts: {
  stdout?: string;
  stderr?: string;
  error?: { code?: string | number; killed?: boolean } | null;
}) {
  mockExecFile.mockImplementation((...args: unknown[]) => {
    const callback = args[3] as (
      err: unknown,
      stdout: string,
      stderr: string,
    ) => void;
    callback(opts.error ?? null, opts.stdout ?? '', opts.stderr ?? '');
  });
}

const SAMPLE_SUMMARY = `Security Posture Summary (last 24 hours)

System Status: Good ✓

--- Hardening ---
  Scans performed:  1 (succeeded: 1, failed: 0)

---
Total events: 1  |  Failed: 0  |  Last event: 5 min ago`;

describe('securityEventsSummaryCommand', () => {
  let context: CommandContext;

  beforeEach(() => {
    vi.clearAllMocks();
    context = createMockCommandContext();
  });

  it('should have correct metadata', () => {
    expect(securityEventsSummaryCommand.name).toBe('security-events-summary');
    expect(securityEventsSummaryCommand.kind).toBe(CommandKind.BUILT_IN);
    expect(securityEventsSummaryCommand.description).toBeTruthy();
  });

  it('passes --summary flag to agent-sec-cli', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('forwards --last-hours to CLI', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours 48');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '48'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('pipes through stdout from agent-sec-cli', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'info' });
    expect((result as { content: string }).content).toBe(SAMPLE_SUMMARY);
  });

  it('ENOENT - binary not found', async () => {
    mockExecFileResult({ error: { code: 'ENOENT' } });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('not found on PATH');
  });

  it('timeout - killed process', async () => {
    mockExecFileResult({ error: { killed: true } });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('timed out');
  });

  it('non-zero exit - traceback stderr falls back to generic message', async () => {
    mockExecFileResult({
      error: { code: 1 },
      stderr:
        '/home/user/.local/lib/python3.11/traceback.py:123 sensitive data',
    });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('exited with code');
    // Verify traceback stderr is NOT in the output
    expect(content).not.toContain('traceback');
    expect(content).not.toContain('sensitive');
  });

  it('non-zero exit - clean CLI error message is forwarded', async () => {
    mockExecFileResult({
      error: { code: 2 },
      stderr: "Error: Invalid value for '--category': 'hhh' is not valid.",
    });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toBe(
      "Error: Invalid value for '--category': 'hhh' is not valid.",
    );
  });

  it('invalid --last-hours value returns error', async () => {
    const result = await securityEventsSummaryCommand.action!(
      context,
      '--last-hours abc',
    );
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('Invalid --last-hours');
  });

  it('caps --last-hours at 720', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours 9999');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '720'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  // --- Empty stdout ---
  it('empty stdout - shows no-events message', async () => {
    mockExecFileResult({ stdout: '' });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'info' });
    const content = (result as { content: string }).content;
    expect(content).toContain('No security events');
    expect(content).toContain('24');
  });

  // --- ENOBUFS ---
  it('ENOBUFS - output exceeded maxBuffer', async () => {
    mockExecFileResult({
      error: { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' },
    });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('exceeded the maximum buffer size');
  });

  // --- extraArgs whitelist ---
  it('drops disallowed flags like --output, --since, --until', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(
      context,
      '--output json --since 2024-01-01 --until 2024-12-31',
    );

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('passes --category flag through to CLI', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--category hardening');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24', '--category', 'hardening'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('passes --event-type flag through to CLI', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--event-type harden');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24', '--event-type', 'harden'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  // --- CLI stderr warning forwarding ---
  it('surfaces CLI warning when stderr has non-traceback content and stdout is empty', async () => {
    mockExecFileResult({
      stdout: '',
      stderr:
        "Warning: Unknown category 'aaa'. Known categories: asset_verify, code_scan, hardening, sandbox, summary",
    });

    const result = await securityEventsSummaryCommand.action!(
      context,
      '--category aaa',
    );
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain("Unknown category 'aaa'");
    expect(content).toContain('hardening');
  });

  it('prepends CLI warning to stdout when both exist', async () => {
    mockExecFileResult({
      stdout: SAMPLE_SUMMARY,
      stderr:
        "Warning: Unknown category 'aaa'. Known categories: asset_verify, code_scan, hardening, sandbox, summary",
    });

    const result = await securityEventsSummaryCommand.action!(context, '');
    const content = (result as { content: string }).content;
    expect(content).toContain("Unknown category 'aaa'");
    expect(content).toContain('Security Posture Summary');
  });

  // --- --last-hours boundary values ---
  it('--last-hours 0 defaults to 24', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours 0');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('--last-hours negative defaults to 24', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours -5');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('--last-hours 721 caps to 720', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours 721');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '720'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('--last-hours float is passed through', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours 2.5');

    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '2.5'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  it('--last-hours without value falls through to default 24', async () => {
    mockExecFileResult({ stdout: SAMPLE_SUMMARY });

    await securityEventsSummaryCommand.action!(context, '--last-hours');

    // --last-hours at end with no value: condition `i + 1 < parts.length`
    // is false, so it's dropped and default 24 is used
    expect(mockExecFile).toHaveBeenCalledWith(
      'agent-sec-cli',
      ['events', '--summary', '--last-hours', '24'],
      expect.any(Object),
      expect.any(Function),
    );
  });

  // --- error.code non-numeric string ---
  it('error.code as non-numeric string falls back to exitCode 1', async () => {
    mockExecFileResult({ error: { code: 'SOME_WEIRD_ERROR' } });

    const result = await securityEventsSummaryCommand.action!(context, '');
    expect(result).toMatchObject({ type: 'message', messageType: 'error' });
    const content = (result as { content: string }).content;
    expect(content).toContain('exited with code 1');
  });
});
