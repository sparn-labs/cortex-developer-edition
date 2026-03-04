/**
 * Command Input — Text input bar for the dashboard command mode.
 *
 * Wraps ink-text-input with a prompt, running indicator, and mode hints.
 */

import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import type React from 'react';
import { useState } from 'react';
import { theme } from '../theme.js';

interface Props {
  onSubmit: (value: string) => void;
  isRunning: boolean;
  runningCommand?: string;
  active: boolean;
}

export function CommandInput({
  onSubmit,
  isRunning,
  runningCommand,
  active,
}: Props): React.ReactElement {
  const [value, setValue] = useState('');

  const handleSubmit = (input: string) => {
    if (input.trim().length === 0) return;
    onSubmit(input.trim());
    setValue('');
  };

  if (isRunning) {
    return (
      <Box paddingX={1}>
        <Text color={theme.synapseViolet}>Running {runningCommand || 'command'}...</Text>
      </Box>
    );
  }

  if (!active) {
    return (
      <Box paddingX={1}>
        <Text color={theme.dimGray}>Press : to enter command mode</Text>
      </Box>
    );
  }

  return (
    <Box paddingX={1}>
      <Text color={theme.neuralCyan}>{'\u276F'} </Text>
      <TextInput
        value={value}
        onChange={setValue}
        onSubmit={handleSubmit}
        focus={active}
        showCursor
      />
      <Text color={theme.dimGray}> [Esc: monitor mode]</Text>
    </Box>
  );
}
