/**
 * KotSafe Full Settings Page
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Implements the complete Settings interface hosting the Activation section,
 * alongside core cybersecurity preferences (Shield, Traffic Inspection, Threat Intel, etc.)
 */

import React, { useState } from 'react';
import { ActivationSection } from './ActivationSection.tsx';
import { Locale, getTranslations } from '../i18n/translations.ts';

interface SettingsPageProps {
  currentLocale?: Locale;
  onLocaleChange?: (locale: Locale) => void;
  isDark?: boolean;
  onThemeToggle?: () => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({
  currentLocale = 'en',
  onLocaleChange,
  isDark = true,
  onThemeToggle,
}) => {
  const [activeCategory, setActiveCategory] = useState<string>('activation');
  const [locale, setLocale] = useState<Locale>(currentLocale);
  const [themeDark, setThemeDark] = useState<boolean>(isDark);

  const t = getTranslations(locale);
  const isRTL = locale === 'ar';

  const handleLocaleSelect = (newLoc: Locale) => {
    setLocale(newLoc);
    onLocaleChange?.(newLoc);
  };

  const handleThemeChange = () => {
    const next = !themeDark;
    setThemeDark(next);
    onThemeToggle?.();
  };

  return (
    <div
      className={`kotsafe-app ${themeDark ? 'theme-dark' : 'theme-light'}`}
      dir={isRTL ? 'rtl' : 'ltr'}
      data-testid="settings-page"
    >
      {/* Top Application Bar */}
      <header className="app-header" role="banner">
        <div className="header-brand">
          <div className="header-logo" aria-hidden="true">
            K
          </div>
          <div className="header-titles">
            <h1 className="header-title">KotSafe Cyber Security</h1>
            <span className="header-badge">v2.0 Tactical</span>
          </div>
        </div>

        <div className="header-actions">
          {/* Language Selector */}
          <div className="locale-selector-wrapper">
            <label htmlFor="locale-select" className="sr-only">
              Select Language
            </label>
            <select
              id="locale-select"
              value={locale}
              onChange={e => handleLocaleSelect(e.target.value as Locale)}
              className="locale-select"
              data-testid="language-selector"
              aria-label="Language selector"
            >
              <option value="en">English (US)</option>
              <option value="es">Español</option>
              <option value="de">Deutsch</option>
              <option value="fr">Français</option>
              <option value="ar">العربية (RTL)</option>
              <option value="ja">日本語</option>
            </select>
          </div>

          {/* Theme Toggle */}
          <button
            type="button"
            className="btn-theme-toggle"
            onClick={handleThemeChange}
            aria-label={themeDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            data-testid="theme-toggle"
          >
            {themeDark ? (
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <circle cx="12" cy="12" r="5" />
                <line x1="12" y1="1" x2="12" y2="3" />
                <line x1="12" y1="21" x2="12" y2="23" />
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                <line x1="1" y1="12" x2="3" y2="12" />
                <line x1="21" y1="12" x2="23" y2="12" />
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
              </svg>
            ) : (
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            )}
          </button>
        </div>
      </header>

      {/* Main Settings Body */}
      <main className="settings-layout" role="main">
        {/* Settings Navigation Sidebar */}
        <nav
          className="settings-nav-sidebar"
          aria-label="Settings Categories"
          data-testid="settings-nav"
        >
          <ul className="settings-nav-list" role="list">
            <li>
              <button
                type="button"
                className={`nav-item ${activeCategory === 'shield' ? 'active' : ''}`}
                onClick={() => setActiveCategory('shield')}
              >
                <svg
                  className="nav-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span>KotSafe Shield</span>
              </button>
            </li>

            <li>
              <button
                type="button"
                className={`nav-item ${activeCategory === 'activation' ? 'active' : ''}`}
                onClick={() => setActiveCategory('activation')}
                aria-current={activeCategory === 'activation' ? 'page' : undefined}
                data-testid="nav-activation-tab"
              >
                <svg
                  className="nav-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <span>License &amp; Activation</span>
                <span className="nav-badge-pill">New</span>
              </button>
            </li>

            <li>
              <button
                type="button"
                className={`nav-item ${activeCategory === 'traffic' ? 'active' : ''}`}
                onClick={() => setActiveCategory('traffic')}
              >
                <svg
                  className="nav-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="10" />
                  <line x1="2" y1="12" x2="22" y2="12" />
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                </svg>
                <span>Traffic &amp; TLS Decryption</span>
              </button>
            </li>

            <li>
              <button
                type="button"
                className={`nav-item ${activeCategory === 'threat' ? 'active' : ''}`}
                onClick={() => setActiveCategory('threat')}
              >
                <svg
                  className="nav-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                </svg>
                <span>Threat Intel APIs</span>
              </button>
            </li>

            <li>
              <button
                type="button"
                className={`nav-item ${activeCategory === 'backup' ? 'active' : ''}`}
                onClick={() => setActiveCategory('backup')}
              >
                <svg
                  className="nav-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" />
                  <polyline points="17 21 17 13 7 13 7 21" />
                  <polyline points="7 3 7 8 15 8" />
                </svg>
                <span>Backup &amp; Restore</span>
              </button>
            </li>
          </ul>
        </nav>

        {/* Content Pane */}
        <section className="settings-content-pane">
          {activeCategory === 'activation' && (
            <ActivationSection
              t={t}
              onUpgradeClick={() => {
                window.open('https://kotsafe.io/pricing', '_blank', 'noopener,noreferrer');
              }}
            />
          )}

          {activeCategory === 'shield' && (
            <div className="settings-placeholder-card">
              <h3>KotSafe Shield Auto-Pilot</h3>
              <p>
                Continuous autonomous monitoring against C2 beaconing, zero-day exploits,
                and telemetry trackers is active.
              </p>
            </div>
          )}

          {activeCategory === 'traffic' && (
            <div className="settings-placeholder-card">
              <h3>Traffic Inspection &amp; SOCKS5 Proxy</h3>
              <p>Configure DoH DoT overrides, root TLS decryption, and upstream SOCKS5 proxies.</p>
            </div>
          )}

          {activeCategory === 'threat' && (
            <div className="settings-placeholder-card">
              <h3>Threat Intelligence Feeds</h3>
              <p>VirusTotal, AlienVault OTX, and Abuse.ch MalwareBazaar integration.</p>
            </div>
          )}

          {activeCategory === 'backup' && (
            <div className="settings-placeholder-card">
              <h3>Backup &amp; Migration</h3>
              <p>Export your encrypted configuration and firewall rules to JSON.</p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};
