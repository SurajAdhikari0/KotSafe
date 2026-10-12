/**
 * KotSafe Feature Tier Comparison Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */

import React from 'react';
import { Translations } from '../i18n/translations.ts';

interface FeatureComparisonProps {
  t: Translations;
}

export const FeatureComparison: React.FC<FeatureComparisonProps> = ({ t }) => {
  return (
    <div className="feature-comparison-card" data-testid="feature-comparison">
      <h4 className="feature-comparison-title">{t.featureComparisonTitle}</h4>

      <div className="comparison-table-wrapper">
        <table className="comparison-table" aria-label="Feature Comparison Matrix">
          <thead>
            <tr>
              <th scope="col">Security Capability</th>
              <th scope="col" className="text-center">{t.freeTierName}</th>
              <th scope="col" className="text-center highlight-col">{t.proTierName}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>P2P Mesh Exit Node Devices</td>
              <td className="text-center">1 Device</td>
              <td className="text-center highlight-col">Up to 6 Devices (Pro) / 50 (Ent)</td>
            </tr>
            <tr>
              <td>Autonomous AI Threat Guard</td>
              <td className="text-center">Basic Static Signatures</td>
              <td className="text-center highlight-col">Real-Time Shannon Entropy &amp; Behavioral Guard</td>
            </tr>
            <tr>
              <td>YARA Memory &amp; Bytecode Inspection</td>
              <td className="text-center text-muted">Locked</td>
              <td className="text-center highlight-col text-success">
                <span className="check-badge">✓ Active</span>
              </td>
            </tr>
            <tr>
              <td>Wireshark PCAPng Full Packet Dumps</td>
              <td className="text-center">Limited Buffer</td>
              <td className="text-center highlight-col text-success">
                <span className="check-badge">✓ Unlimited Extended Metadata</span>
              </td>
            </tr>
            <tr>
              <td>Zero-Latency Cloud Relay &amp; Mesh</td>
              <td className="text-center text-muted">Standard Relay</td>
              <td className="text-center highlight-col text-success">
                <span className="check-badge">✓ Dedicated TURN / WireGuard Tunnel</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};
