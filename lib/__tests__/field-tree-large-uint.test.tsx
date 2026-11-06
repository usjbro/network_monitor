// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { FieldTree } from '@/components/FieldTree';
import { THEMES } from '@/lib/osi-engine';

afterEach(cleanup);

describe('FieldTree with a uint sent as a string', () => {
  it('shows the digits of a value above 2^53 - 1', () => {
    render(
      <FieldTree
        fields={[{
          path: 'http.content_length', label: 'Content-Length', type: 'uint',
          value: '9007199254740993', region: 'payload', offset: 0, len: 10,
        }]}
        theme={THEMES.matrix}
        selectedPath={null}
        highlightedPaths={new Set()}
        onSelectField={() => {}}
        onHoverField={() => {}}
      />,
    );
    expect(screen.getByText('9007199254740993', { exact: false })).toBeInTheDocument();
  });
});
