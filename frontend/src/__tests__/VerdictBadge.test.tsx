import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { VerdictBadge } from '../components/VerdictBadge';
import { StatusBadge } from '../components/StatusBadge';
import type { Verdict } from '../types/api';

describe('VerdictBadge Component', () => {
  const verdicts: Array<{ verdict: Verdict; expectedText: string; expectedClass: string }> = [
    { verdict: 'PROVEN_EXPOSURE', expectedText: 'PROVEN EXPOSURE', expectedClass: 'badge-red' },
    { verdict: 'PROVEN_AFFECTED', expectedText: 'PROVEN AFFECTED', expectedClass: 'badge-red' },
    { verdict: 'POTENTIALLY_AFFECTED', expectedText: 'POTENTIALLY AFFECTED', expectedClass: 'badge-amber' },
    { verdict: 'UNKNOWN', expectedText: 'UNKNOWN', expectedClass: 'badge-amber' },
    { verdict: 'CONTRADICTORY', expectedText: 'CONTRADICTORY', expectedClass: 'badge-amber' },
    { verdict: 'NOT_VERIFIED', expectedText: 'NOT VERIFIED', expectedClass: 'badge-amber' },
    { verdict: 'PROVEN_NOT_AFFECTED', expectedText: 'PROVEN NOT AFFECTED', expectedClass: 'badge-green' },
  ];

  verdicts.forEach(({ verdict, expectedText, expectedClass }) => {
    it(`renders ${verdict} with correct accessible label and class`, () => {
      render(<VerdictBadge verdict={verdict} />);
      const badge = screen.getByRole('status');
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass(expectedClass);
      expect(badge).toHaveTextContent(expectedText);
      expect(badge).toHaveAttribute('aria-label', `Verdict: ${expectedText}`);
    });
  });
});

describe('StatusBadge Component', () => {
  it('renders REACHABLE with red variant', () => {
    render(<StatusBadge status="REACHABLE" />);
    const badge = screen.getByRole('status');
    expect(badge).toHaveClass('badge-red');
    expect(badge).toHaveTextContent('REACHABLE');
  });

  it('renders NOT_REACHABLE with green variant', () => {
    render(<StatusBadge status="NOT_REACHABLE" />);
    const badge = screen.getByRole('status');
    expect(badge).toHaveClass('badge-green');
    expect(badge).toHaveTextContent('NOT REACHABLE');
  });

  it('renders UNKNOWN with amber variant', () => {
    render(<StatusBadge status="UNKNOWN" />);
    const badge = screen.getByRole('status');
    expect(badge).toHaveClass('badge-amber');
  });
});
