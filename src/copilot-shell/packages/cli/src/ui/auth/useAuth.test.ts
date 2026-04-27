/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import type { Config } from '@copilot-shell/core';
import { AuthType } from '@copilot-shell/core';
import type { LoadedSettings } from '../../config/settings.js';
import { useAuthCommand } from './useAuth.js';

vi.mock('../hooks/useQwenAuth.js', () => ({
  useQwenAuth: () => ({
    qwenAuthState: undefined,
    cancelQwenAuth: vi.fn(),
  }),
}));

describe('useAuthCommand', () => {
  const createMockSettings = (): LoadedSettings =>
    ({
      merged: {
        security: {
          auth: {},
        },
      },
      setValue: vi.fn(),
    }) as unknown as LoadedSettings;

  const createMockConfig = (): Config =>
    ({
      getAuthType: vi.fn(() => undefined),
      getModelsConfig: vi.fn(() => ({})),
      refreshAuth: vi.fn(),
      getContentGenerator: vi.fn(() => undefined),
      getContentGeneratorConfig: vi.fn(() => undefined),
      updateCredentials: vi.fn(),
      getUsageStatisticsEnabled: vi.fn(() => false),
    }) as unknown as Config;

  it('restores bash option after canceling OpenAI auth when startup allows bash', async () => {
    const settings = createMockSettings();
    const config = createMockConfig();
    const addItem = vi.fn();

    const { result } = renderHook(() =>
      useAuthCommand(settings, config, addItem, true),
    );

    await act(async () => {
      await result.current.handleAuthSelect(AuthType.USE_OPENAI);
    });

    expect(result.current.showBashOptionInAuthDialog).toBe(false);
    expect(result.current.isAuthenticating).toBe(true);

    act(() => {
      result.current.cancelAuthentication();
    });

    expect(result.current.isAuthenticating).toBe(false);
    expect(result.current.isAuthDialogOpen).toBe(true);
    expect(result.current.showBashOptionInAuthDialog).toBe(true);
  });

  it('keeps bash option hidden after cancel when startup does not allow bash', async () => {
    const settings = createMockSettings();
    const config = createMockConfig();
    const addItem = vi.fn();

    const { result } = renderHook(() =>
      useAuthCommand(settings, config, addItem, false),
    );

    await act(async () => {
      await result.current.handleAuthSelect(AuthType.USE_OPENAI);
    });

    act(() => {
      result.current.cancelAuthentication();
    });

    expect(result.current.isAuthDialogOpen).toBe(true);
    expect(result.current.showBashOptionInAuthDialog).toBe(false);
  });
});
